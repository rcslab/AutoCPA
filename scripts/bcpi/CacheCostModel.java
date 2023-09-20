package bcpi;

import bcpi.type.BcpiStruct;
import bcpi.type.Field;
import bcpi.type.Layout;

import ghidra.program.model.data.Structure;

import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * A cost model for field accesses based on accessed cache lines.
 */
public class CacheCostModel implements CostModel<Layout> {
	private static final int CACHE_LINE = 64;

	private final AccessPatterns patterns;
	private final BcpiStruct original;
	private final int align;

	public CacheCostModel(AccessPatterns patterns, BcpiStruct original) {
		this.patterns = patterns;
		this.original = original;

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

	@Override
	public long cost(Layout layout) {
		int[] bytePerm = getBytePermutation(layout);

		// As a heuristic, assume offset zero is twice as likely as the next possible
		// offset, which is twice as likely as the next one, etc.
		int nOffsets = CACHE_LINE / this.align;
		long totalWeight = (1L << nOffsets) - 1;
		int nCacheLines = 1 + (layout.getByteSize() + CACHE_LINE - 1) / CACHE_LINE;
		BitSet touchedLines = new BitSet(nCacheLines);

		// Compute the expected cost over the possible cache line offsets
		long total = 0;
		int weightShift = nOffsets;
		for (int i = 0; i < nOffsets; ++i) {
			int offset = i * this.align;

			// For each offset, the cost is the cumulative number of cache lines touched
			// up to the current pattern, weighted by the pattern's observation count.
			// You can think of this like the area under the (pattern, cache lines) curve.
			touchedLines.clear();

			long cost = 0;
			for (AccessPattern pattern : this.patterns.getRankedPatterns(this.original)) {
				long count = this.patterns.getCount(pattern);

				pattern.getBytes()
					.stream()
					.map(j -> bytePerm[j])
					.filter(j -> j >= 0)
					.forEach(j -> touchedLines.set((offset + j) / CACHE_LINE));

				cost += count * touchedLines.cardinality();

				if (touchedLines.get(0)) {
					// Break ties by slightly preferring the first cache line
					cost -= 1;
				}
			}

			--weightShift;
			total += cost << weightShift;
		}

		// Normalize the score
		long cost = (total + totalWeight - 1) / totalWeight;

		// Penalize internal padding
		cost += layout.getInternalPaddingBytes();

		return cost;
	}

	public long cost(Structure struct) {
		return cost(BcpiStruct.from(struct).getLayout());
	}
}
