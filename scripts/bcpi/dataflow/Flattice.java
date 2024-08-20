package bcpi.dataflow;

import java.util.Objects;
import java.util.Optional;

/**
 * A simple one-element lattice with top and bottom elements.
 */
public final class Flattice<T> implements Lattice<Flattice<T>> {
	private T element;
	private boolean top;

	private Flattice(T element, boolean top) {
		this.element = element;
		this.top = top;
	}

	/**
	 * @return The empty (bottom) lattice element.
	 */
	public static <U> Flattice<U> bottom() {
		return new Flattice<>(null, false);
	}

	/**
	 * @return Whether this is the bottom lattice element.
	 */
	public boolean isBottom() {
		return this.element == null && !this.top;
	}

	/**
	 * @return The universal (top) lattice element.
	 */
	public static <U> Flattice<U> top() {
		return new Flattice<>(null, true);
	}

	/**
	 * @return Whether this is the top lattice element.
	 */
	public boolean isTop() {
		return this.top;
	}

	/**
	 * @return The lattice element wrapping the given object.
	 */
	public static <U> Flattice<U> of(U element) {
		return new Flattice<>(Objects.requireNonNull(element), false);
	}

	/**
	 * @return The lattice element wrapping the given object, otherwise bottom().
	 */
	public static <U> Flattice<U> ofOptional(Optional<U> element) {
		return new Flattice<>(element.orElse(null), false);
	}

	/**
	 * @return The wrapped element, if any.
	 */
	public Optional<T> get() {
		return Optional.ofNullable(this.element);
	}

	/**
	 * @return Whether the wrapped element is known.
	 */
	public boolean isPresent() {
		return this.element != null;
	}

	@Override
	public Flattice<T> copy() {
		return new Flattice<>(this.element, this.top);
	}

	@Override
	public boolean joinInPlace(Flattice<T> other) {
		if (isTop() || other.isBottom() || this.equals(other)) {
			return false;
		} else if (isBottom()) {
			this.element = other.element;
			this.top = other.top;
		} else {
			this.element = null;
			this.top = true;
		}

		return true;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof Flattice)) {
			return false;
		}

		var other = (Flattice<?>) obj;
		return Objects.equals(this.element, other.element)
			&& this.top == other.top;
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.element, this.top);
	}

	@Override
	public String toString() {
		if (isBottom()) {
			return "⊥";
		} else if (isTop()) {
			return "⊤";
		} else {
			return "{" + this.element + "}";
		}
	}
}
