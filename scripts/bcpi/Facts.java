package bcpi;

import java.util.Objects;

/**
 * Data flow facts.
 */
class Facts {
	private final Lattice<Field> field;
	private final boolean array;

	Facts() {
		this(Lattice.none(), false);
	}

	private Facts(Lattice<Field> field, boolean array) {
		this.field = field;
		this.array = array;
	}

	/**
	 * @return A copy of these facts, overriding the struct field.
	 */
	Facts withField(Field field) {
		return new Facts(Lattice.of(field), this.array);
	}

	/**
	 * @return A copy of these facts, overriding the array flag.
	 */
	Facts withArray(boolean array) {
		return new Facts(this.field, array);
	}

	/**
	 * @return The struct field associated with this varnode, if any.
	 */
	Field getField() {
		return this.field.get();
	}

	/**
	 * @return Whether this varnode is part of an array.
	 */
	boolean isArray() {
		return this.array;
	}

	/**
	 * Compute the lattice meet of two data flow facts.
	 */
	Facts meet(Facts other) {
		return new Facts(
			this.field.meet(other.field),
			this.array & other.array
		);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof Facts)) {
			return false;
		}

		Facts other = (Facts) obj;
		return this.field.equals(other.field)
			&& this.array == other.array;
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.field, this.array);
	}

	@Override
	public String toString() {
		String fieldStr;
		Field field = this.field.get();
		if (field == null) {
			fieldStr = this.field.toString();
		} else {
			String parent = field.getParent().getName();
			String name = field.getFieldName();
			fieldStr = String.format("{%s::%s}", parent, name);
		}
		return String.format("{field: %s, array: %s}", fieldStr, this.array);
	}
}
