package bcpi.type;

import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataTypeComponent;

/**
 * Struct/union fields.
 */
public final class Field {
	private final DataTypeComponent ghidra;
	private final BcpiAggregate parent;
	private final BcpiType type;
	private final String name;
	private final int startBit;
	private final int index;
	private final int origIndex;

	Field(DataTypeComponent ghidra, BcpiAggregate parent, BcpiType type, String name, int startBit, int index, int origIndex) {
		this.ghidra = ghidra;
		this.parent = parent;
		this.type = type;
		this.name = name;
		this.startBit = startBit;
		this.index = index;
		this.origIndex = origIndex;
	}

	static Field from(DataTypeComponent field, BcpiAggregate parent, int index) {
		var type = BcpiType.from(field.getDataType());
		var startBit = 8 * field.getOffset();
		if (field.isBitFieldComponent()) {
			var bitField = (BitFieldDataType)type.toGhidra();
			startBit += bitField.getBitOffset();
		}

		return new Field(field, parent, type, field.getFieldName(), startBit, index, index);
	}

	/**
	 * @return Ghidra's representation of this field.
	 */
	public DataTypeComponent toGhidra() {
		return this.ghidra;
	}

	/**
	 * @return The aggregate type containing this field.
	 */
	public BcpiAggregate getParent() {
		return this.parent;
	}

	/**
	 * @return This field's type.
	 */
	public BcpiType getType() {
		return this.type;
	}

	/**
	 * @return This field's name.
	 */
	public String getName() {
		return this.name;
	}

	/**
	 * @return The byte offset of this field within its parent.
	 */
	public int getStartByte() {
		return this.startBit / 8;
	}

	/**
	 * @return The bit offset of this field within its parent.
	 */
	public int getStartBit() {
		return this.startBit;
	}

	/**
	 * @return The (exclusive) end byte of this field.
	 */
	public int getEndByte() {
		return (getEndBit() + 7) / 8;
	}

	/**
	 * @return The (exclusive) end bit of this field.
	 */
	public int getEndBit() {
		return this.startBit + this.getBitSize();
	}

	/**
	 * @return The size of this field in bytes.
	 */
	public int getByteSize() {
		return this.type.getByteSize();
	}

	/**
	 * @return The size of this field in bits.
	 */
	public int getBitSize() {
		return this.type.getBitSize();
	}

	/**
	 * @return The index of this field within the layout.
	 */
	public int getIndex() {
		return this.index;
	}

	/**
	 * @return The index of this field within the original layout.
	 */
	public int getOriginalIndex() {
		return this.origIndex;
	}

	/**
	 * @return A copy of this field at a different position.
	 */
	public Field reorder(int startBit, int index) {
		return new Field(this.ghidra, this.parent, this.type, this.name, startBit, index, this.origIndex);
	}

	@Override
	public String toString() {
		String cdecl = this.type.toC(this.parent.getName() + "::" + this.name);

		String index;
		if (this.origIndex == this.index) {
			index = String.format("%d", this.index);
		} else {
			index = String.format("%d->%d", this.index, this.origIndex);
		}

		String range;
		var startBit = getStartBit();
		var endBit = getEndBit();
		if (this.type instanceof BcpiBitField || startBit % 8 != 0 || endBit % 8 != 0) {
			range = String.format("[%d.%d, %d.%d)", startBit / 8, startBit % 8, endBit / 8, endBit % 8);
		} else {
			range = String.format("[%d, %d)", startBit / 8, endBit / 8);
		}

		return String.format("%s /* %s: %s */", cdecl, index, range);
	}
}
