package bcpi;

import java.util.Objects;

/**
 * A simple one-element lattice with top and bottom elements.
 */
class Lattice<T> {
	private final T element;
	private final boolean known;

	private Lattice(T element, boolean known) {
		this.element = element;
		this.known = known;
	}

	/**
	 * @return The lattice element wrapping the given object.
	 */
	static <U> Lattice<U> of(U element) {
		return new Lattice<>(Objects.requireNonNull(element), true);
	}

	/**
	 * @return The empty (top) lattice element.
	 */
	static <U> Lattice<U> none() {
		return new Lattice<>(null, true);
	}

	/**
	 * @return The unknown (bottom) lattice element.
	 */
	static <U> Lattice<U> unknown() {
		return new Lattice<>(null, false);
	}

	/**
	 * @return The wrapped element, if any.
	 */
	T get() {
		return this.element;
	}

	/**
	 * @return Whether this lattice element is none.
	 */
	boolean isNone() {
		return this.element == null && this.known;
	}

	/**
	 * @return Whether this lattice element is unknown.
	 */
	boolean isUnknown() {
		return !this.known;
	}

	/**
	 * @return The meet of two lattice elements.
	 */
	Lattice<T> meet(Lattice<T> other) {
		if (isNone()) {
			return other;
		} else if (isUnknown()) {
			return this;
		} else if (other.isNone()) {
			return this;
		} else if (other.isUnknown()) {
			return other;
		} else if (this.element.equals(other.element)) {
			return this;
		} else {
			return unknown();
		}
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof Lattice)) {
			return false;
		}

		Lattice<?> other = (Lattice<?>) obj;
		return Objects.equals(this.element, other.element)
			&& this.known == other.known;
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.element, this.known);
	}

	@Override
	public String toString() {
		if (isNone()) {
			return "⊤";
		} else if (isUnknown()) {
			return "⊥";
		} else {
			return "{" + this.element + "}";
		}
	}
}
