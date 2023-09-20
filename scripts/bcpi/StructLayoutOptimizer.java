package bcpi;

import ghidra.program.model.data.Structure;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Optimizes struct layouts via a constrained hill-climbing algorithm.
 */
public class StructLayoutOptimizer {
	private final AccessPatterns patterns;
	private final Structure original;
	private final StructAbiConstraints constraints;
	private final CostModel<Structure> costModel;
	private final int align;

	public StructLayoutOptimizer(AccessPatterns patterns, Structure original, StructAbiConstraints constraints, CostModel<Structure> costModel) {
		this.patterns = patterns;
		this.original = original;
		this.constraints = constraints;
		this.costModel = costModel;
		this.align = DataTypes.getAlignment(original);
	}

	/**
	 * @return The optimized layout for the structure.
	 */
	public Structure optimize() {
		List<Field> origFields = Field.allFields(this.original);
		List<Field> fields = new ArrayList<>();
		Set<Field> added = new HashSet<>();

		// Add fields with fixed positions first
		for (Field field : origFields) {
			if (this.constraints.isFixed(field)) {
				pack(fields, field);
				added.add(field);
			}
		}

		// Then access patterns from most common to least
		for (AccessPattern pattern : patterns.getRankedPatterns(this.original)) {
			pattern.getLegacyFields()
				.stream()
				.filter(f -> !added.contains(f))
				.sorted(Comparator.comparingInt(f -> f.getOrdinal()))
				.forEach(f -> pack(fields, f));

			added.addAll(pattern.getLegacyFields());
		}

		// Add any missing fields we didn't see
		origFields
			.stream()
			.filter(f -> !added.contains(f))
			.forEach(f -> pack(fields, f));

		return build(fields);
	}

	/**
	 * Pack a new field into a structure.
	 */
	private void pack(List<Field> fields, Field field) {
		fields.add(field);

		int bestI = -1;
		long bestCost = -1;
		for (int i = fields.size() - 1; ; --i) {
			if (this.constraints.check(fields)) {
				long newCost = this.costModel.cost(build(fields));
				if (bestI < 0 || newCost < bestCost) {
					bestI = i;
					bestCost = newCost;
				}
			}

			if (i == 0) {
				break;
			}
			Collections.swap(fields, i - 1, i);
		}

		if (bestI < 0) {
			throw new RuntimeException("Unsatisfiable constraints for " + field);
		}

		// The new field will be at index zero.  Rotate it into place.
		Collections.rotate(fields.subList(0, bestI + 1), -1);
	}

	/**
	 * Make a copy of a structure with reordered fields.
	 */
	private Structure build(List<Field> fields) {
		Structure result = DataTypes.emptyStructLike(this.original);
		for (Field field : fields) {
			field.copyTo(result);
		}
		DataTypes.padTail(result, this.align);
		return result;
	}
}
