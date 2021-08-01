package bcpi;

import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.Structure;

import com.google.common.collect.ImmutableList;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * An individual addressable field (which may contain multiple bitfields).
 */
public class Field {
	private final Structure parent;
	private final DataType type;
	private final int offset;
	private final int endOffset;
	private final List<DataTypeComponent> components;

	private Field(Structure parent, DataType type, int offset, int endOffset, List<DataTypeComponent> components) {
		this.parent = parent;
		this.type = type;
		this.offset = offset;
		this.endOffset = endOffset;
		this.components = ImmutableList.copyOf(components);
	}

	/**
	 * @return All the fields in the given structure.
	 */
	public static List<Field> allFields(Structure struct) {
		List<Field> fields = new ArrayList<>();

		List<DataTypeComponent> components = new ArrayList<>();
		DataType type = null;
		int offset = 0, endOffset = 0;

		for (DataTypeComponent component : struct.getComponents()) {
			int curOffset = component.getOffset();
			if (curOffset >= endOffset) {
				if (!components.isEmpty()) {
					fields.add(new Field(struct, type, offset, endOffset, components));
					components.clear();
				}

				type = component.getDataType();
				offset = curOffset;
				if (component.isBitFieldComponent()) {
					type = ((BitFieldDataType) type).getBaseDataType();
					endOffset = offset + type.getLength();
				} else {
					endOffset = component.getEndOffset();
				}
			}

			components.add(component);
		}

		if (!components.isEmpty()) {
			fields.add(new Field(struct, type, offset, endOffset, components));
		}

		return ImmutableList.copyOf(fields);
	}

	/**
	 * @return The field at the given byte offset in a structure.
	 */
	public static Field atOffset(Structure parent, int offset) {
		// TODO: Do better than linear scan.  parent.getComponentAt() by itself won't work
		// because it may put us in the middle of a bitfield.
		for (Field field : allFields(parent)) {
			if (offset >= field.offset && offset < field.endOffset) {
				return field;
			}
		}

		return null;
	}

	/**
	 * @return The structure this field comes from.
	 */
	public Structure getParent() {
		return this.parent;
	}

	/**
	 * @return The type of this field.
	 */
	public DataType getDataType() {
		return this.type;
	}

	/**
	 * @return The name of this field.
	 */
	public String getFieldName() {
		return this.components.get(0).getFieldName();
	}

	/**
	 * @return The components that make up this field, potentially multiple for bitfields.
	 */
	public List<DataTypeComponent> getComponents() {
		return this.components;
	}

	/**
	 * @return The byte offset of this field in the structure.
	 */
	public int getOffset() {
		return this.offset;
	}

	/**
	 * @return The byte offset of the end of this field in the structure.
	 */
	public int getEndOffset() {
		return this.endOffset;
	}

	/**
	 * @return Whether this is a padding field.
	 */
	public boolean isPadding() {
		return type.equals(DefaultDataType.dataType);
	}

	/**
	 * @return Whether the given component is padding.
	 */
	public static boolean isPadding(DataTypeComponent component) {
		return component.getDataType().equals(DefaultDataType.dataType);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof Field)) {
			return false;
		}

		Field other = (Field) obj;
		return this.parent.equals(other.parent)
			&& this.type.equals(other.type)
			&& this.offset == other.offset
			&& this.endOffset == other.endOffset
			&& this.components.equals(other.components);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.parent, this.type, this.offset, this.endOffset, this.components);
	}

	@Override
	public String toString() {
		return String.format("%s::%s", this.parent.getName(), this.getFieldName());
	}
}
