package bcpi;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.HashMultiset;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Multiset;
import com.google.common.collect.Multisets;
import com.google.common.collect.SetMultimap;

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
	private final Map<Function, ControlFlowGraph> cfgs = new HashMap<>();
	private final BcpiData data;
	private final FieldReferences refs;
	private long samples = 0;
	private long attributed = 0;

	private AccessPatterns(BcpiData data, FieldReferences refs) {
		this.data = data;
		this.refs = refs;
	}

	/**
	 * Infer access patterns from the collected data.
	 */
	public static AccessPatterns collect(BcpiData data, FieldReferences refs, TaskMonitor monitor) throws Exception {
		AccessPatterns patterns = new AccessPatterns(data, refs);
		patterns.collect(monitor);
		return patterns;
	}

	private void collect(TaskMonitor monitor) throws Exception {
		// Add coverage information to the CFGs
		for (Address address : this.data.getAddresses()) {
			BcpiDataRow row = this.data.getRow(address);
			int count = row.getCount(BcpiConfig.INSTRUCTION_COUNTER);
			ControlFlowGraph cfg = getCfg(row.function, monitor);
			cfg.addCoverage(address, count);
		}

		// Find access patterns associated with cache misses
		for (Address baseAddress : this.data.getAddresses()) {
			Map<Structure, Set<DataTypeComponent>> pattern = new HashMap<>();
			int count = this.data.getCount(baseAddress, BcpiConfig.CACHE_MISS_COUNTER);

			Set<CodeBlock> blocks = getCodeBlocksThrough(baseAddress, monitor);
			for (CodeBlock block : blocks) {
				for (Address address : block.getAddresses(true)) {
					if (!BcpiConfig.ANALYZE_BACKWARD_FLOW && block.contains(baseAddress) && address.compareTo(baseAddress) < 0) {
						// Don't count accesses before the miss
						continue;
					}

					for (DataTypeComponent field : this.refs.getFields(address)) {
						Structure struct = (Structure) field.getParent();
						pattern.computeIfAbsent(struct, k -> new HashSet<>())
							.add(field);
					}
				}
			}

			this.samples += count;
			if (!pattern.isEmpty()) {
				this.attributed += count;
			}

			for (Map.Entry<Structure, Set<DataTypeComponent>> entry : pattern.entrySet()) {
				AccessPattern accessPattern = new AccessPattern(entry.getValue());
				this.patterns.computeIfAbsent(entry.getKey(), k -> HashMultiset.create())
					.add(accessPattern, count);
				this.functions.put(accessPattern, this.data.getRow(baseAddress).function);
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
	 * @return The cached CFG for a function.
	 */
	private ControlFlowGraph getCfg(Function function, TaskMonitor monitor) throws Exception {
		ControlFlowGraph cfg = this.cfgs.get(function);
		if (cfg == null) {
			cfg = new ControlFlowGraph(function, monitor);
			this.cfgs.put(function, cfg);
		}
		return cfg;
	}

	/**
	 * @return All the code blocks that flow through the given address.
	 */
	private Set<CodeBlock> getCodeBlocksThrough(Address address, TaskMonitor monitor) throws Exception {
		BcpiDataRow row = this.data.getRow(address);

		ControlFlowGraph cfg = getCfg(row.function, monitor);
		Set<CodeBlock> blocks = new HashSet<>(cfg.getLikelyReachedBlocks(address));
		Set<CodeBlock> prevBlocks = blocks;
		for (int i = 0; i < BcpiConfig.IPA_DEPTH; ++i) {
			Set<CodeBlock> calledBlocks = getCalledBlocks(prevBlocks, monitor);
			blocks.addAll(calledBlocks);
			prevBlocks = calledBlocks;
		}

		return blocks;
	}

	/**
	 * @return All the code blocks that are reached by function calls from the given blocks.
	 */
	private Set<CodeBlock> getCalledBlocks(Set<CodeBlock> blocks, TaskMonitor monitor) throws Exception {
		Set<CodeBlock> result = new HashSet<>();

		for (CodeBlock block : blocks) {
			CodeBlockReferenceIterator dests = block.getDestinations(monitor);
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

				ControlFlowGraph cfg = getCfg(function, monitor);
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
	private int getCount(DataTypeComponent field) {
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
