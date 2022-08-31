package bcpi;

import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;

import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * A cost model for field accesses based on accessed cache lines.
 */
public class CacheCostModel implements CostModel<Structure> {
	private static final int CACHE_LINE = 64;

	private final AccessPatterns patterns;
	private final Structure original;
	private final List<Field> originalFields;
	private final int align;

	public CacheCostModel(AccessPatterns patterns, Structure original) {
		this.patterns = patterns;
		this.original = original;
		this.originalFields = Field.allFields(original);

		if (BcpiConfig.ASSUME_CACHE_ALIGNED) {
			this.align = CACHE_LINE;
		} else {
			// Structures are not necessarily allocated at the beginning of a cache line
			int align = DataTypes.getAlignment(original);
			// Assume allocations are at least pointer-aligned
			align = Math.max(align, original.getDataOrganization().getDefaultPointerAlignment());
			align = Math.min(align, CACHE_LINE);
			this.align = align;
		}
	}

	/**
	 * Compute a fast mapping between the original and optimized fields, since the
	 * access patterns refer to the original fields.
	 */
	private int[] getFieldPermutation(List<Field> fields) {
		Map<String, Field> fieldMap = fields
			.stream()
			.collect(Collectors.toMap(f -> f.getFieldName(), f -> f));

		int[] bytePerm = new int[this.original.getLength()];
		Arrays.fill(bytePerm, -1);

		for (Field origField : this.originalFields) {
			Field optField = fieldMap.get(origField.getFieldName());
			if (optField == null) {
				continue;
			}

			int start = origField.getOffset();
			int end = Math.min(origField.getEndOffset(), bytePerm.length);
			int delta = optField.getOffset() - start;
			for (int i = start; i < end; ++i) {
				bytePerm[i] = i + delta;
			}
		}

		return bytePerm;
	}

	@Override
	public long cost(Structure struct) {
		List<Field> fields = Field.allFields(struct);
		int[] bytePerm = getFieldPermutation(fields);

		// As a heuristic, assume offset zero is twice as likely as the next possible
		// offset, which is twice as likely as the next one, etc.
		int nOffsets = CACHE_LINE / this.align;
		long totalWeight = (1L << nOffsets) - 1;
		int nCacheLines = 1 + (struct.getLength() + CACHE_LINE - 1) / CACHE_LINE;
		BitSet touchedLines = new BitSet(nCacheLines);

		// Compute the expected cost over the possible cache line offsets
		long total = 0;
		int weightShift = nOffsets;
		for (int offset = 0; offset < CACHE_LINE; offset += this.align) {
			// For each offset, the cost is the cumulative number of cache lines touched
			// up to the current pattern, weighted by the pattern's observation count.
			// You can think of this like the area under the (pattern, cache lines) curve.
			touchedLines.clear();

			long cost = 0;
			for (AccessPattern pattern : this.patterns.getRankedPatterns(this.original)) {
				long count = this.patterns.getCount(pattern);

				pattern.getBytes()
					.stream()
					.map(i -> bytePerm[i])
					.filter(i -> i >= 0)
					.forEach(i -> touchedLines.set(i / CACHE_LINE));

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
		int padding = 0;
		for (DataTypeComponent field : struct.getComponents()) {
			if (Field.isPadding(field)) {
				padding += field.getLength();
			} else {
				cost += padding;
				padding = 0;
			}
		}

		return cost;
	}
}
