package bcpi.dataflow;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * A powerset lattice.
 */
public final class SetLattice<T> implements Lattice<SetLattice<T>> {
	private final Set<T> set;

	private SetLattice(Set<T> set) {
		this.set = set;
	}

	/**
	 * @return The empty (bottom) lattice element.
	 */
	public static <U> SetLattice<U> bottom() {
		return new SetLattice<>(new HashSet<>());
	}

	/**
	 * @return Whether this is the bottom lattice element.
	 */
	public boolean isBottom() {
		return this.set.isEmpty();
	}

	/**
	 * @return A singleton set.
	 */
	public static <U> SetLattice<U> singleton(U element) {
		SetLattice<U> ret = bottom();
		ret.add(element);
		return ret;
	}

	/**
	 * @return The set of elements.
	 */
	public Set<T> get() {
		return Collections.unmodifiableSet(this.set);
	}

	/**
	 * Add an element to this set.
	 *
	 * @return Whether this set changed.
	 */
	public boolean add(T element) {
		return this.set.add(element);
	}

	@Override
	public SetLattice<T> copy() {
		return new SetLattice<>(new HashSet<>(this.set));
	}

	@Override
	public boolean joinInPlace(SetLattice<T> other) {
		return this.set.addAll(other.set);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof SetLattice)) {
			return false;
		}

		var other = (SetLattice<?>) obj;
		return this.set.equals(other.set);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.set);
	}

	@Override
	public String toString() {
		if (isBottom()) {
			return "⊥";
		} else {
			return this.set.toString();
		}
	}
}
