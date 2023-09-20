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
import java.util.stream.IntStream;

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

	private static class LayoutAndCost {
		final Layout layout;
		final long cost;

		LayoutAndCost(Layout layout, long cost) {
			this.layout = layout;
			this.cost = cost;
		}
	}

	private static final Comparator<LayoutAndCost> LOWEST_COST_FIRST = Comparator
		.<LayoutAndCost>comparingLong(lac -> lac.cost);

	/**
	 * Calculate the cost of inserting a field at a position.
	 */
	private LayoutAndCost cost(Layout layout, Field field, int i) {
		var newLayout = layout.prefix(i);
		newLayout.add(field);

		var fields = layout.getFields();
		for (int j = i; j < fields.size(); ++j) {
			newLayout.add(fields.get(j));
		}

		var cost = this.costModel.cost(newLayout);
		return new LayoutAndCost(newLayout, cost);
	}

	/**
	 * Pack a new field into a structure.
	 */
	private Layout pack(Layout layout, Field field) {
		var best = IntStream.rangeClosed(0, layout.getFields().size())
			.parallel()
			.mapToObj(i -> cost(layout, field, i))
			.min(LOWEST_COST_FIRST)
			.orElseThrow(() -> new RuntimeException("Unsatisfiable constraints for " + field));

		return best.layout;
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
