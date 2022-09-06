package bcpi;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * A set of fields accessed in a block.
 */
public class AccessPattern {
	private final Composite type;
	private final BitSet read;
	private final BitSet written;

	public AccessPattern(Composite type, BitSet read, BitSet written) {
		this.type = type;
		this.read = (BitSet) read.clone();
		this.written = (BitSet) written.clone();
	}

	/**
	 * @return The type this access pattern applies to.
	 */
	public Composite getType() {
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
		return (BitSet) this.read.clone();
	}

	/**
	 * @return The bytes written by this pattern.
	 */
	public BitSet getWrittenBytes() {
		return (BitSet) this.written.clone();
	}

	/**
	 * @return All the fields accessed by this pattern.
	 */
	public List<Field> getFields() {
		return Field.allFields((Structure) this.type)
			.stream()
			.filter(this::accesses)
			.collect(Collectors.toList());
	}

	/**
	 * @return Whether a field is accessed by this pattern.
	 */
	public boolean accesses(Field field) {
		BitSet bytes = new BitSet();
		bytes.set(field.getOffset(), field.getEndOffset());
		return this.read.intersects(bytes) || this.written.intersects(bytes);
	}

	/**
	 * @return Whether a field is accessed by this pattern.
	 */
	public boolean accesses(DataTypeComponent field) {
		BitSet bytes = new BitSet();
		bytes.set(field.getOffset(), field.getEndOffset() + 1);
		return this.read.intersects(bytes) || this.written.intersects(bytes);
	}

	/**
	 * @return Whether a field is read by this pattern.
	 */
	public boolean reads(Field field) {
		BitSet bytes = new BitSet();
		bytes.set(field.getOffset(), field.getEndOffset());
		return this.read.intersects(bytes);
	}

	/**
	 * @return Whether a field is read by this pattern.
	 */
	public boolean reads(DataTypeComponent field) {
		BitSet bytes = new BitSet();
		bytes.set(field.getOffset(), field.getEndOffset() + 1);
		return this.read.intersects(bytes);
	}

	/**
	 * @return Whether a field is written by this pattern.
	 */
	public boolean writes(Field field) {
		BitSet bytes = new BitSet();
		bytes.set(field.getOffset(), field.getEndOffset());
		return this.written.intersects(bytes);
	}

	/**
	 * @return Whether a field is written by this pattern.
	 */
	public boolean writes(DataTypeComponent field) {
		BitSet bytes = new BitSet();
		bytes.set(field.getOffset(), field.getEndOffset() + 1);
		return this.written.intersects(bytes);
	}

	/**
	 * @return The portion of this access pattern that applies to a field,
	 *         or null if the field is not a composite.
	 */
	public AccessPattern project(DataTypeComponent field) {
		DataType type = field.getDataType();
		type = DataTypes.resolve(type);
		if (type instanceof Composite) {
			type = DataTypes.dedup(type);
			BitSet read = this.read.get(field.getOffset(), field.getEndOffset() + 1);
			BitSet written = this.written.get(field.getOffset(), field.getEndOffset() + 1);
			return new AccessPattern((Composite) type, read, written);
		} else {
			return null;
		}
	}

	@Override
	public String toString() {
		return toString(DataTypes.formatCDecl(this.type) + "::");
	}

	private String toString(String prefix) {
		List<String> fields = new ArrayList<>();

		for (DataTypeComponent field : this.type.getDefinedComponents()) {
			if (!accesses(field)) {
				continue;
			}

			AccessPattern proj = project(field);
			if (proj == null) {
				String r = reads(field) ? "R" : "";
				String w = writes(field) ? "W" : "";
				fields.add(String.format("%s(%s%s)", field.getFieldName(), r, w));
			} else {
				fields.add(proj.toString(field.getFieldName() + "."));
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
