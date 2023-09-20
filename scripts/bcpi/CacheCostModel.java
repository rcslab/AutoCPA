package bcpi;

import bcpi.type.BcpiStruct;
import bcpi.type.Field;
import bcpi.type.Layout;

import ghidra.program.model.data.Structure;

import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

/**
 * A cost model for field accesses based on accessed cache lines.
 */
public class CacheCostModel implements CostModel<Layout> {
	private static final int CACHE_LINE = 64;

	private final AccessPatterns patterns;
	private final BcpiStruct original;
	private final List<AccessPattern> rankedPatterns;
	private final int align;
	private final int nOffsets;

	public CacheCostModel(AccessPatterns patterns, BcpiStruct original) {
		this.patterns = patterns;
		this.original = original;
		this.rankedPatterns = patterns.getRankedPatterns(original);

		if (BcpiConfig.ASSUME_CACHE_ALIGNED) {
			this.align = CACHE_LINE;
		} else {
			// Structures are not necessarily allocated at the beginning of a cache line
			int align = original.getByteAlignment();
			// Assume allocations are at least pointer-aligned
			align = Math.max(align, original.toGhidra().getDataOrganization().getDefaultPointerAlignment());
			align = Math.min(align, CACHE_LINE);
			this.align = align;
		}

		this.nOffsets = CACHE_LINE / this.align;
	}

	/**
	 * Compute a fast mapping between the original and optimized bytes, since the
	 * access patterns refer to the original layout.
	 */
	private int[] getBytePermutation(Layout layout) {
		var oldFields = this.original.getFields();
		var bytePerm = new int[this.original.getByteSize()];
		Arrays.fill(bytePerm, -1);

		for (var newField : layout.getFields()) {
			var oldField = oldFields.get(newField.getOriginalIndex());
			int start = oldField.getStartByte();
			int end = oldField.getEndByte();
			int delta = newField.getStartByte() - start;
			for (int i = start; i < end; ++i) {
				bytePerm[i] = i + delta;
			}
		}

		return bytePerm;
	}

	/**
	 * @return The weighted cost for the given offset.
	 */
	private long weightedCost(long cost, int offset) {
                // As a heuristic, assume offset zero is twice as likely as the next possible
                // offset, which is twice as likely as the next one, etc.
		return cost << (this.nOffsets - offset - 1);
	}

	/**
	 * @return The total weight of all offsets.
	 */
	private long totalWeight() {
		return (1L << this.nOffsets) - 1;
	}

	/**
	 * Calculate the cost for a structure at a particular cache line offset.
	 */
	private long costAtOffset(int offset, int[] bytePerm) {
		int byteOffset = offset * this.align;

		// For each offset, the cost is the cumulative number of cache lines touched
		// up to the current pattern, weighted by the pattern's observation count.
		// You can think of this like the area under the (pattern, cache lines) curve.
		var touchedLines = new BitSet();
		long cost = 0;

		for (var pattern : this.rankedPatterns) {
			long count = this.patterns.getCount(pattern);

			pattern.getBytes()
				.stream()
				.map(b -> bytePerm[b])
				.filter(b -> b >= 0)
				.forEach(b -> touchedLines.set((byteOffset + b) / CACHE_LINE));

			cost += count * touchedLines.cardinality();

			if (!touchedLines.get(0)) {
				// Break ties by slightly preferring the first cache line
				cost += 1;
			}
		}

		return weightedCost(cost, offset);
	}

	@Override
	public long cost(Layout layout) {
		int[] bytePerm = getBytePermutation(layout);

		// Compute the expected cost over the possible cache line offsets
		long cost = IntStream.range(0, this.nOffsets)
			.parallel()
			.mapToLong(i -> costAtOffset(i, bytePerm))
			.sum();

		// Normalize the score
		long weight = totalWeight();
		cost = (cost + weight - 1) / weight;

		// Penalize internal padding
		cost += layout.getInternalPaddingBytes();

		return cost;
	}

	public long cost(Structure struct) {
		return cost(BcpiStruct.from(struct).getLayout());
	}
}
