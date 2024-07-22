package bcpi;

import bcpi.type.BcpiStruct;
import bcpi.type.Field;
import bcpi.type.Layout;
import bcpi.util.BeamSearch;
import bcpi.util.BeamState;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
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
		var fields = this.original.getFields();
		var order = new Field[fields.size()];
		var added = new BitSet(fields.size());

		// Add fields with fixed positions at the right places
		for (var field : fields) {
			int i = this.constraints.getFixed(field);
			if (i >= 0) {
				addField(order, i, field, added);
			}
		}

		// Then access patterns from most common to least
		int i = 0;
		for (var pattern : patterns.getRankedPatterns(this.original)) {
			for (var field : pattern.getFields()) {
				i = addField(order, i, field, added);
			}
		}

		// Add any missing fields we didn't see
		for (var field : this.original.getFields()) {
			i = addField(order, i, field, added);
		}

		var layout = this.original.getLayout().emptyCopy();
		var beam = new BeamSearch<>(new BeamLayout(layout, order))
			.search(BcpiConfig.LAYOUT_BEAM_WIDTH, 1);
		if (beam.isEmpty()) {
			throw new IllegalArgumentException("Unsatisfiable constraints for " + this.original);
		}
		return beam.get(0).layout;
	}

	/**
	 * Add a field to the insertion order.
	 */
	private static int addField(Field[] order, int i, Field field, BitSet added) {
		int j = field.getOriginalIndex();
		if (!added.get(j)) {
			while (order[i] != null) {
				i++;
			}
			order[i++] = field;

			added.set(j);
		}
		return i;
	}

	/**
	 * An in-progress layout for beam search.
	 */
	private class BeamLayout implements BeamState<BeamLayout> {
		final Layout layout;
		final Field[] order;
		final long cost;

		BeamLayout(Layout layout, Field[] order) {
			this.layout = layout;
			this.order = order;
			this.cost = costModel.cost(layout);
		}

		@Override
		public boolean isFinal() {
			return this.layout.getFields().size() == this.order.length;
		}

		private Layout insertField(Field field, int i) {
			var ret = this.layout.prefix(i);
			ret.add(field);

			var fields = layout.getFields();
			for (int j = i; j < fields.size(); ++j) {
				ret.add(fields.get(j));
			}

			return ret;
		}

		@Override
		public List<BeamLayout> successors() {
			if (isFinal()) {
				return List.of();
			}

			var i = this.layout.getFields().size();
			var field = this.order[i];
			return IntStream.rangeClosed(0, i)
				.parallel()
				.mapToObj(j -> insertField(field, j))
				.filter(constraints::check)
				.map(l -> new BeamLayout(l, this.order))
				.collect(Collectors.toList());
		}

		@Override
		public int compareTo(BeamLayout other) {
			// Beam search selects the "top" k, so put lower costs last
			int ret = Long.compare(other.cost, this.cost);
			if (ret != 0) {
				return ret;
			}

			// For equal costs, prefer orders more similar to the original
			ret = Integer.compare(ulam(other.layout), ulam(this.layout));
			if (ret != 0) {
				return ret;
			}

			// Break further ties with lexicographic field order
			var ourFields = this.layout.getFields();
			var theirFields = other.layout.getFields();
			int size = Math.min(ourFields.size(), theirFields.size());
			for (int i = 0; i < size; ++i) {
				int j = ourFields.get(i).getOriginalIndex();
				int k = theirFields.get(i).getOriginalIndex();
				ret = Integer.compare(j, k);
				if (ret != 0) {
					return ret;
				}
			}

			return Integer.compare(ourFields.size(), theirFields.size());
		}

		/**
		 * Calculate the Ulam distance of a field permutation, i.e. the
		 * edit distance from the original layout.
		 */
		private static int ulam(Layout layout) {
			// Ulam distance is len(sequence) - len(longest increasing subsequence)
			var fields = layout.getFields();
			var size = fields.size();
			if (size == 0) {
				return 0;
			}

			var lis = new int[size];
			int i = 0;
			lis[i] = fields.get(0).getOriginalIndex();

			for (int j = 1; j < size; ++j) {
				int x = fields.get(j).getOriginalIndex();
				if (x > lis[i]) {
					lis[++i] = x;
				} else {
					// Arrays.binarySearch() returns (-k - 1) == ~k
					// for an insertion point k
					int k = ~Arrays.binarySearch(lis, 0, i + 1, x);
					lis[k] = x;
				}
			}

			return size - i - 1;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			} else if (obj instanceof BeamLayout other) {
				return this.layout.equals(other.layout);
			} else {
				return false;
			}
		}

		@Override
		public int hashCode() {
			return Objects.hash(this.layout);
		}
	}
}
