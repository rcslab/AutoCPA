package bcpi;

import bcpi.type.BcpiAggregate;
import bcpi.type.BcpiArray;
import bcpi.type.BcpiType;
import bcpi.type.Field;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * A set of fields accessed in a block.
 */
public class AccessPattern {
	private final BcpiAggregate type;
	private final BitSet read;
	private final BitSet written;

	public AccessPattern(BcpiAggregate type, BitSet read, BitSet written) {
		var size = Math.max(read.length(), written.length());
		if (size > type.getByteSize()) {
			throw new IllegalArgumentException(String.format(
				"%d-byte access pattern is larger than %d-byte %s",
				size, type.getByteSize(), type));
		}

		this.type = type;
		this.read = (BitSet)read.clone();
		this.written = (BitSet)written.clone();
	}

	/**
	 * @return The type this access pattern applies to.
	 */
	public BcpiAggregate getType() {
		return this.type;
	}

	/**
	 * @return All the bytes accessed by this pattern.
	 */
	public BitSet getBytes() {
		BitSet bytes = getReadBytes();
		bytes.or(this.written);
		return bytes;
	}

	/**
	 * @return The bytes read by this pattern.
	 */
	public BitSet getReadBytes() {
		return (BitSet)this.read.clone();
	}

	/**
	 * @return The bytes written by this pattern.
	 */
	public BitSet getWrittenBytes() {
		return (BitSet)this.written.clone();
	}

	/**
	 * @return All the fields accessed by this pattern.
	 */
	public List<Field> getFields() {
		return this.type.getFields()
			.stream()
			.filter(this::accesses)
			.collect(Collectors.toList());
	}

	/**
	 * Check that a field is from the right type.
	 */
	private void checkFieldParent(Field field) {
		if (!field.getParent().equals(this.type)) {
			throw new IllegalArgumentException(String.format(
				"Field %s is not from type %s", field, this.type));
		}
	}

	/**
	 * @return Whether a field is accessed by this pattern.
	 */
	public boolean accesses(Field field) {
		checkFieldParent(field);

		BitSet bytes = new BitSet();
		bytes.set(field.getStartByte(), field.getEndByte());
		return this.read.intersects(bytes) || this.written.intersects(bytes);
	}

	/**
	 * @return Whether a field is read by this pattern.
	 */
	public boolean reads(Field field) {
		checkFieldParent(field);

		BitSet bytes = new BitSet();
		bytes.set(field.getStartByte(), field.getEndByte());
		return this.read.intersects(bytes);
	}

	/**
	 * @return Whether a field is written by this pattern.
	 */
	public boolean writes(Field field) {
		checkFieldParent(field);

		BitSet bytes = new BitSet();
		bytes.set(field.getStartByte(), field.getEndByte());
		return this.written.intersects(bytes);
	}

	/**
	 * @return The portion of this access pattern that applies to a field,
	 *         or null if the field is not a composite.
	 */
	public AccessPattern project(Field field) {
		checkFieldParent(field);

		var type = field.getType().resolve();
		int start = field.getStartByte();
		int end = start + type.getByteSize();
		BitSet read = this.read.get(start, end);
		BitSet written = this.written.get(start, end);

		// Unwrap arrays and merge accesses to different elements
		while (type instanceof BcpiArray) {
			var array = (BcpiArray)type;
			type = array.unwrap().resolve();

			int size = type.getByteSize();
			BitSet newRead = new BitSet(size);
			BitSet newWritten = new BitSet(size);
			for (int i = 0, j = 0; i < array.getCount(); ++i, j += size) {
				newRead.or(read.get(j, j + size));
				newWritten.or(written.get(j, j + size));
			}

			read = newRead;
			written = newWritten;
		}

		if (type instanceof BcpiAggregate) {
			return new AccessPattern((BcpiAggregate)type, read, written);
		} else {
			return null;
		}
	}

	@Override
	public String toString() {
		return toString(this.type.toC() + "::");
	}

	private String toString(String prefix) {
		List<String> fields = new ArrayList<>();

		for (var field : this.type.getFields()) {
			if (!accesses(field)) {
				continue;
			}

			AccessPattern proj = project(field);
			if (proj == null) {
				String r = reads(field) ? "R" : "";
				String w = writes(field) ? "W" : "";
				fields.add(String.format("%s(%s%s)", field.getName(), r, w));
			} else {
				fields.add(proj.toString(field.getName() + "."));
			}
		}

		if (fields.size() == 1) {
			return prefix + fields.get(0);
		} else {
			return fields
				.stream()
				.collect(Collectors.joining(", ", prefix + "{", "}"));
		}
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof AccessPattern)) {
			return false;
		}

		AccessPattern other = (AccessPattern) obj;
		return this.type.equals(other.type)
			&& this.read.equals(other.read)
			&& this.written.equals(other.written);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.type, this.read, this.written);
	}
}
