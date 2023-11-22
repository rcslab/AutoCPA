package bcpi.util;

import java.util.List;
import java.util.PriorityQueue;
import java.util.stream.Collectors;

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
		var best = new PriorityQueue<T>();
		var beam = List.of(this.init);

		while (!beam.isEmpty()) {
			for (T item : beam) {
				if (item.isFinal()) {
					best.offer(item);
					if (best.size() > limit) {
						best.poll();
					}
				}
			}

			beam = beam.parallelStream()
				.unordered()
				.flatMap(s -> s.successors().stream())
				.distinct()
				.sorted()
				.limit(width)
				.collect(Collectors.toList());
		}

		return List.copyOf(best);
	}
}
