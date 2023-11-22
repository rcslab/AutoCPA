package bcpi.util;

import java.util.Collection;

/**
 * An element of state space for beam search.
 */
public interface BeamState<T> extends Comparable<T> {
	/**
	 * @return Whether to include this state in the search results.
	 */
	boolean isFinal();

	/**
	 * @return All states that can be reached from this state.
	 */
	Collection<T> successors();
}
