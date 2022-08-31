package bcpi;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;

import com.google.common.collect.Sets;

import java.util.BitSet;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.LongAdder;
import java.util.stream.Collectors;

/**
 * Struct field access patterns.
 */
public class AccessPatterns {
	// Stores the access patterns for each struct
	private final ConcurrentMap<Structure, Set<AccessPattern>> patterns = new ConcurrentHashMap<>();
	private final ConcurrentMap<AccessPattern, LongAdder> counts = new ConcurrentHashMap<>();
	private final ConcurrentMap<AccessPattern, Set<Function>> functions = new ConcurrentHashMap<>();
	private final LongAdder samples = new LongAdder();
	private final LongAdder attributed = new LongAdder();
	private final BcpiControlFlow cfgs;
	private final FieldReferences refs;

	public AccessPatterns(BcpiControlFlow cfgs, FieldReferences refs) {
		this.cfgs = cfgs;
		this.refs = refs;
	}

	/**
	 * Infer access patterns from the collected data.
	 */
	public void collect(BcpiData data) {
		// Find access patterns associated with cache misses
		Collection<BcpiDataRow> rows = data.getRows();
		Msg.info(this, String.format("Collecting access patterns from %,d instructions", rows.size()));
		rows.parallelStream().forEach(this::collect);
	}

	private void collect(BcpiDataRow row) {
		long count = row.getCount(BcpiConfig.CACHE_MISS_COUNTER);
		if (count == 0) {
			return;
		}

		Map<Structure, BitSet> reads = new HashMap<>();
		Map<Structure, BitSet> writes = new HashMap<>();

		Set<CodeBlock> blocks = getCodeBlocksThrough(row.function, row.address);
		for (CodeBlock block : blocks) {
			for (Address address : block.getAddresses(true)) {
				if (!BcpiConfig.ANALYZE_BACKWARD_FLOW && block.contains(row.address) && address.compareTo(row.address) < 0) {
					// Don't count accesses before the miss
					continue;
				}

				for (FieldReference ref : this.refs.getFields(address)) {
					for (FieldReference structRef : ref.getStructRefs()) {
						(structRef.isRead() ? reads : writes)
							.computeIfAbsent((Structure) structRef.getOuterType(), k -> new BitSet())
							.set(structRef.getOffset(), structRef.getEndOffset());
					}
				}
			}
		}

		this.samples.add(count);
		if (!reads.isEmpty() || !writes.isEmpty()) {
			this.attributed.add(count);
		}

		for (Structure struct : Sets.union(reads.keySet(), writes.keySet())) {
			BitSet read = reads.getOrDefault(struct, new BitSet());
			BitSet written = writes.getOrDefault(struct, new BitSet());
			AccessPattern pattern = new AccessPattern(struct, read, written);
			this.patterns
				.computeIfAbsent(struct, k -> ConcurrentHashMap.newKeySet())
				.add(pattern);
			this.counts
				.computeIfAbsent(pattern, k -> new LongAdder())
				.add(count);
			this.functions
				.computeIfAbsent(pattern, k -> ConcurrentHashMap.newKeySet())
				.add(row.function);
		}
	}

	/**
	 * @return The fraction of samples that we found an access pattern for.
	 */
	public double getHitRate() {
		return (double) this.attributed.sum() / this.samples.sum();
	}

	/**
	 * @return All the code blocks that flow through the given address.
	 */
	private Set<CodeBlock> getCodeBlocksThrough(Function func, Address address) {
		ControlFlowGraph cfg = this.cfgs.getCfg(func);
		return cfg.getLikelyReachedBlocks(address);
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
	public List<AccessPattern> getRankedPatterns(Structure struct) {
		return this.patterns
			.getOrDefault(struct, Collections.emptySet())
			.stream()
			.sorted(Comparator
				.<AccessPattern>comparingLong(this::getCount)
				.reversed())
			.collect(Collectors.toList());
	}

	/**
	 * @return The total number of accesses to a struct.
	 */
	public long getCount(Structure struct) {
		return this.patterns
			.getOrDefault(struct, Collections.emptySet())
			.stream()
			.mapToLong(this::getCount)
			.sum();
	}

	/**
	 * @return The number of occurrences of an access pattern.
	 */
	public long getCount(AccessPattern pattern) {
		return this.counts
			.getOrDefault(pattern, new LongAdder())
			.sum();
	}

	/**
	 * @return The functions which had the given access pattern.
	 */
	public Set<Function> getFunctions(AccessPattern pattern) {
		return Optional.ofNullable(this.functions.get(pattern))
			.map(Collections::unmodifiableSet)
			.orElseGet(Collections::emptySet);
	}
}
