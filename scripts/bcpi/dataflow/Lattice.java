package bcpi.dataflow;

import java.util.Collection;

/**
 * A join semi-lattice.
 */
public interface Lattice<T extends Lattice<T>> {
	/**
	 * @return A new instance with the same value as this.
	 */
	T copy();

	/**
	 * Calculate the join (least upper bound) of this and other, updating
	 * this instance in-place.
	 *
	 * @return Whether this value changed.
	 */
	boolean joinInPlace(T other);

	/**
	 * Calculate the join (least upper bound) of this and many others,
	 * updating this instance in-place.
	 *
	 * @return Whether this value changed.
	 */
	default boolean joinInPlace(Collection<T> others) {
		var ret = false;
		for (var other : others) {
			ret |= joinInPlace(other);
		}
		return ret;
	}

	/**
	 * @return The join of this and other.
	 */
	default T join(T other) {
		var ret = copy();
		ret.joinInPlace(other);
		return ret;
	}

	/**
	 * @return The join of this and many others.
	 */
	default T join(Collection<T> others) {
		var ret = copy();
		ret.joinInPlace(others);
		return ret;
	}
}
