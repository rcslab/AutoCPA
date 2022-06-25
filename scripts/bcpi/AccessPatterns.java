package bcpi;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

import com.google.common.base.Throwables;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.HashMultiset;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Multiset;
import com.google.common.collect.Multisets;
import com.google.common.collect.SetMultimap;
import com.google.common.collect.Sets;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Struct field access patterns.
 */
public class AccessPatterns {
	// Stores the access patterns for each struct
	private final Map<Structure, Multiset<AccessPattern>> patterns = new HashMap<>();
	private final SetMultimap<AccessPattern, Function> functions = HashMultimap.create();
	private final BcpiControlFlow cfgs;
	private final FieldReferences refs;
	private long samples = 0;
	private long attributed = 0;

	public AccessPatterns(BcpiControlFlow cfgs, FieldReferences refs) {
		this.cfgs = cfgs;
		this.refs = refs;
	}

	/**
	 * Infer access patterns from the collected data.
	 */
	public void collect(BcpiData data) {
		// Find access patterns associated with cache misses
		for (Address baseAddress : data.getAddresses()) {
			Function func = data.getRow(baseAddress).function;

			Map<Structure, Set<Field>> reads = new HashMap<>();
			Map<Structure, Set<Field>> writes = new HashMap<>();
			int count = data.getCount(baseAddress, BcpiConfig.CACHE_MISS_COUNTER);

			Set<CodeBlock> blocks = getCodeBlocksThrough(func, baseAddress);
			for (CodeBlock block : blocks) {
				for (Address address : block.getAddresses(true)) {
					if (!BcpiConfig.ANALYZE_BACKWARD_FLOW && block.contains(baseAddress) && address.compareTo(baseAddress) < 0) {
						// Don't count accesses before the miss
						continue;
					}

					for (FieldReference ref : this.refs.getFields(address)) {
						Field field = ref.getField();
						Structure struct = field.getParent();
						(ref.isRead() ? reads : writes)
							.computeIfAbsent(struct, k -> new HashSet<>())
							.add(field);
					}
				}
			}

			this.samples += count;
			if (!reads.isEmpty() || !writes.isEmpty()) {
				this.attributed += count;
			}

			for (Structure struct : Sets.union(reads.keySet(), writes.keySet())) {
				Set<Field> read = reads.getOrDefault(struct, Collections.emptySet());
				Set<Field> written = writes.getOrDefault(struct, Collections.emptySet());
				AccessPattern pattern = new AccessPattern(read, written);
				this.patterns
					.computeIfAbsent(struct, k -> HashMultiset.create())
					.add(pattern, count);
				this.functions.put(pattern, func);
			}
		}
	}

	/**
	 * @return The fraction of samples that we found an access pattern for.
	 */
	public double getHitRate() {
		return (double) this.attributed / this.samples;
	}

	/**
	 * @return All the code blocks that flow through the given address.
	 */
	private Set<CodeBlock> getCodeBlocksThrough(Function func, Address address) {
		try {
			ControlFlowGraph cfg = this.cfgs.getCfg(func);
			Set<CodeBlock> blocks = new HashSet<>(cfg.getLikelyReachedBlocks(address));
			Set<CodeBlock> prevBlocks = blocks;
			for (int i = 0; i < BcpiConfig.IPA_DEPTH; ++i) {
				Set<CodeBlock> calledBlocks = getCalledBlocks(prevBlocks);
				blocks.addAll(calledBlocks);
				prevBlocks = calledBlocks;
			}
			return blocks;
		} catch (Exception e) {
			throw Throwables.propagate(e);
		}
	}

	/**
	 * @return All the code blocks that are reached by function calls from the given blocks.
	 */
	private Set<CodeBlock> getCalledBlocks(Set<CodeBlock> blocks) throws Exception {
		Set<CodeBlock> result = new HashSet<>();

		for (CodeBlock block : blocks) {
			CodeBlockReferenceIterator dests = block.getDestinations(TaskMonitor.DUMMY);
			while (dests.hasNext()) {
				CodeBlockReference dest = dests.next();
				if (!dest.getFlowType().isCall()) {
					continue;
				}

				CodeBlock destBlock = dest.getDestinationBlock();
				Address address = destBlock.getMinAddress();
				Function function = destBlock.getModel().getProgram().getListing().getFunctionContaining(address);
				if (function != null && function.isThunk()) {
					function = function.getThunkedFunction(true);
				}
				if (function == null) {
					continue;
				}

				long size = function.getBody().getNumAddresses();
				if (size <= 0 || size >= BcpiConfig.MAX_INLINE_SIZE) {
					continue;
				}

				ControlFlowGraph cfg = this.cfgs.getCfg(function);
				result.addAll(cfg.getLikelyReachedBlocks(address));
			}
		}

		return result;
	}

	/**
	 * @return All the structures about which we have data.
	 */
	public Set<Structure> getStructures() {
		return Collections.unmodifiableSet(this.patterns.keySet());
	}

	/**
	 * @return All the access patterns we saw for a structure, from most to least often.
	 */
	public Set<AccessPattern> getPatterns(Structure struct) {
		return ImmutableSet.copyOf(
			Multisets.copyHighestCountFirst(this.patterns.get(struct))
				.elementSet()
		);
	}

	/**
	 * @return The total number of accesses to a struct.
	 */
	public int getCount(Structure struct) {
		return this.patterns.get(struct).size();
	}

	/**
	 * @return The number of occurrences of an access pattern.
	 */
	public int getCount(Structure struct, AccessPattern pattern) {
		return this.patterns.get(struct).count(pattern);
	}

	/**
	 * @return The number of accesses we have to this field.
	 */
	private int getCount(Field field) {
		int count = 0;
		Multiset<AccessPattern> patterns = this.patterns.get(field.getParent());
		if (patterns != null) {
			for (Multiset.Entry<AccessPattern> entry : patterns.entrySet()) {
				if (entry.getElement().getFields().contains(field)) {
					count += entry.getCount();
				}
			}
		}
		return count;
	}

	/**
	 * @return The functions which had the given access pattern.
	 */
	public Set<Function> getFunctions(AccessPattern pattern) {
		return Collections.unmodifiableSet(this.functions.get(pattern));
	}
}
