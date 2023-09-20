package bcpi;

import bcpi.type.BcpiStruct;
import bcpi.type.Field;
import bcpi.type.Layout;

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
	private final BcpiStruct original;
	private final StructAbiConstraints constraints;
	private final CostModel<Layout> costModel;
	private final int align;

	public StructLayoutOptimizer(AccessPatterns patterns, BcpiStruct original, StructAbiConstraints constraints, CostModel<Layout> costModel) {
		this.patterns = patterns;
		this.original = original;
		this.constraints = constraints;
		this.costModel = costModel;
		this.align = original.getByteAlignment();
	}

	/**
	 * @return The optimized layout for the structure.
	 */
	public Structure optimize() {
		Layout layout = this.original.getLayout().emptyCopy();
		Set<Field> added = new HashSet<>();

		// Add fields with fixed positions first
		for (var field : this.original.getFields()) {
			if (this.constraints.isFixed(field)) {
				layout = pack(layout, field);
				added.add(field);
			}
		}

		// Then access patterns from most common to least
		for (var pattern : patterns.getRankedPatterns(this.original)) {
			for (var field : pattern.getFields()) {
				if (added.add(field)) {
					layout = pack(layout, field);
				}
			}
		}

		// Add any missing fields we didn't see
		for (var field : this.original.getFields()) {
			if (added.add(field)) {
				layout = pack(layout, field);
			}
		}

		return build(layout);
	}

	/**
	 * Pack a new field into a structure.
	 */
	private Layout pack(Layout layout, Field field) {
		Layout best = null;
		long bestCost = Long.MAX_VALUE;
		int nFields = layout.getFields().size();
		for (int i = 0; i <= nFields; ++i) {
			var copy = layout.prefix(i);
			copy.add(field);
			for (var after : layout.getFields().subList(i, nFields)) {
				copy.add(after);
			}

			if (this.constraints.check(copy)) {
				var cost = this.costModel.cost(copy);
				if (cost <= bestCost) {
					best = copy;
					bestCost = cost;
				}
			}
		}

		if (best == null) {
			throw new RuntimeException("Unsatisfiable constraints for " + field);
		}

		return best;
	}

	/**
	 * Make a copy of a structure with reordered fields.
	 */
	private Structure build(Layout layout) {
		Structure result = DataTypes.emptyStructLike(this.original.toGhidra());
		for (var field : layout.getFields()) {
			DataTypes.addField(result, field.toGhidra());
		}
		DataTypes.padTail(result, this.align);
		return result;
	}
}
