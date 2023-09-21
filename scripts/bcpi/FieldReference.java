package bcpi;

import bcpi.type.BcpiAggregate;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Metadata about a struct field reference.
 */
public class FieldReference {
	private final BcpiAggregate outerType;
	private final boolean outerArray;
	private final int offset;
	private final int size;
	private final boolean read;

	FieldReference(BcpiAggregate outerType, boolean outerArray, int offset, int size, boolean read) {
		Objects.checkFromIndexSize(offset, size, outerType.getByteSize());
		this.outerType = outerType;
		this.outerArray = outerArray;
		this.offset = offset;
		this.size = size;
		this.read = read;
	}

	/**
	 * @return The type of the outermost object whose field is being accessed.
	 */
	public BcpiAggregate getOuterType() {
		return this.outerType;
	}

	/**
	 * @return Whether the outermost object is part of an array.
	 */
	public boolean isOuterArray() {
		return this.outerArray;
	}

	/**
	 * @return The offset of the memory access into the outer object.
	 */
	public int getOffset() {
		return this.offset;
	}

	/**
	 * @return The size of this memory access in bytes.
	 */
	public int getSize() {
		return this.size;
	}

	/**
	 * @return The (exclusive) end offset of the memory access into the outer object.
	 */
	public int getEndOffset() {
		return this.offset + this.size;
	}

	/**
	 * @return Whether this access was a read access.
	 */
	public boolean isRead() {
		return this.read;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof FieldReference)) {
			return false;
		}

		FieldReference other = (FieldReference) obj;
		return this.outerType.equals(other.outerType)
			&& this.outerArray == other.outerArray
			&& this.offset == other.offset
			&& this.size == other.size
			&& this.read == other.read;
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.outerType, this.outerArray, this.offset, this.size, this.read);
	}

	@Override
	public String toString() {
		String type = this.outerType.toC();
		String array = this.outerArray ? "[]" : "";
		String rw = this.read ? "R" : "W";
		return String.format("(%s%s + %d)%s(%d)", type, array, this.offset, rw, this.size);
	}
}
