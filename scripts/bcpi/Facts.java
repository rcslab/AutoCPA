package bcpi;

import ghidra.program.model.data.Composite;
import ghidra.program.model.pcode.Varnode;

import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;

/**
 * Data flow facts.
 */
class Facts {
	private final Lattice<Composite> type;
	private final Lattice<Integer> offset;
	private final boolean array;

	Facts() {
		this(Lattice.none(), Lattice.none(), false);
	}

	private Facts(Lattice<Composite> type, Lattice<Integer> offset, boolean array) {
		this.type = type;
		this.offset = offset;
		this.array = array;
	}

	/**
	 * Create the initial facts for a Varnode.
	 */
	static Facts initial(Varnode vn) {
		Optional<Composite> dataType = Optional
			.ofNullable(vn.getHigh().getDataType()) // Get the type of the pointer varnode
			.flatMap(DataTypes::dereference)        // Dereference it
			.map(DataTypes::resolve)                // Resolve typedefs
			.filter(t -> t instanceof Composite)    // Filter out non-structs/unions
			.map(DataTypes::dedup)                  // Deduplicate it
			.map(t -> (Composite) t);

		Lattice<Composite> type = dataType
			.map(Lattice::of)
			.orElseGet(Lattice::none);
		Lattice<Integer> offset = dataType
			.map(t -> Lattice.of(0))
			.orElseGet(Lattice::none);

		return new Facts(type, offset, false);
	}

	/**
	 * @return A copy of these facts, overriding the type.
	 */
	Facts withType(Composite type) {
		Lattice<Composite> typeFact = Lattice.of(type);
		Lattice<Integer> offset = this.offset;
		if (!this.type.equals(typeFact)) {
			offset = Lattice.of(0);
		}
		return new Facts(typeFact, offset, this.array);
	}

	/**
	 * @return A copy of these facts, with an additional offset.
	 */
	Facts addOffset(int offset) {
		Integer original = this.offset.get();
		if (original == null) {
			return this;
		} else {
			return new Facts(this.type, Lattice.of(original + offset), this.array);
		}
	}

	/**
	 * @return A copy of these facts, overriding the array flag.
	 */
	Facts withArray(boolean array) {
		return new Facts(this.type, this.offset, array);
	}

	/**
	 * @return Whether a type is known for this varnode.
	 */
	boolean hasType() {
		return this.type.get() != null;
	}

	/**
	 * @return The type pointed to by this varnode, if known.
	 */
	Composite getType() {
		return this.type.get();
	}

	/**
	 * @return Whether an offset is known for this varnode.
	 */
	boolean hasOffset() {
		return this.offset.get() != null;
	}

	/**
	 * @return The offset into the allocation, if known.
	 */
	OptionalInt getOffset() {
		Integer offset = this.offset.get();
		if (offset == null) {
			return OptionalInt.empty();
		} else {
			return OptionalInt.of(offset);
		}
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
			this.type.meet(other.type),
			this.offset.meet(other.offset),
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
		return this.type.equals(other.type)
			&& this.offset.equals(other.offset)
			&& this.array == other.array;
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.type, this.offset, this.array);
	}

	@Override
	public String toString() {
		String typeStr;
		Composite type = this.getType();
		if (type == null) {
			typeStr = this.type.toString();
		} else {
			typeStr = String.format("{%s}", type.getName());
		}
		return String.format("{type: %s, offset: %s, array: %s}", typeStr, this.offset, this.array);
	}
}
