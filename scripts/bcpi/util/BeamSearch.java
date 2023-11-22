package bcpi.util;

import java.util.List;
import java.util.TreeSet;
import java.util.stream.Collector;

/**
 * Generic beam search implementation.
 */
public final class BeamSearch<T extends BeamState<T>> {
	private final T init;

	/**
	 * Create a BeamSearch from an initial state.
	 */
	public BeamSearch(T init) {
		this.init = init;
	}

	/**
	 * Run beam search.
	 */
	public List<T> search(int width, int limit) {
		var best = new TreeSet<T>();
		var beam = List.of(this.init);

		while (!beam.isEmpty()) {
			beam.stream()
				.filter(T::isFinal)
				.forEach(item -> addAndTrim(best, item, limit));

			beam = beam.parallelStream()
				.unordered()
				.flatMap(s -> s.successors().stream())
				.collect(topK(width));
		}

		return toList(best);
	}

	/**
	 * Add an item to a sorted set, keeping the top k elements.
	 */
	private void addAndTrim(TreeSet<T> set, T item, int k) {
		set.add(item);
		while (set.size() > k) {
			set.pollFirst();
		}
	}

	/**
	 * Convert a sorted set to a list in descending order.
	 */
	private List<T> toList(TreeSet<T> set) {
		return List.copyOf(set.descendingSet());
	}

	/**
	 * @return A collector that outputs the top k elements.
	 */
	private Collector<T, ?, List<T>> topK(int k) {
		return Collector.<T, TreeSet<T>, List<T>>of(
			TreeSet::new,
			(set, item) -> addAndTrim(set, item, k),
			(left, right) -> {
				right.forEach(item -> addAndTrim(left, item, k));
				return left;
			},
			this::toList,
			Collector.Characteristics.UNORDERED
		);
	}
}
