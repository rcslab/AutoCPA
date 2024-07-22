package bcpi;

import bcpi.type.BcpiStruct;
import bcpi.type.Field;
import bcpi.type.Layout;

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
	public Layout optimize() {
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

		return layout;
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
	 * Insert a field into a layout.
	 */
	private Layout insertField(Layout layout, Field field, int i) {
		var ret = layout.prefix(i);
		ret.add(field);

		var fields = layout.getFields();
		for (int j = i; j < fields.size(); ++j) {
			ret.add(fields.get(j));
		}

		return ret;
	}

	/**
	 * Pack a new field into a structure.
	 */
	private Layout pack(Layout layout, Field field) {
		var best = IntStream.rangeClosed(0, layout.getFields().size())
			.parallel()
			.mapToObj(i -> insertField(layout, field, i))
			.filter(this.constraints::check)
			.map(l -> new LayoutAndCost(l, this.costModel.cost(l)))
			.min(LOWEST_COST_FIRST)
			.orElseThrow(() -> new RuntimeException("Unsatisfiable constraints for " + field));

		return best.layout;
	}
}
