package bcpi.type;

import ghidra.program.model.data.BitFieldDataType;

/**
 * BCPI bit-field type.
 */
public final class BcpiBitField extends AbstractType {
	private final BcpiType wrapped;
	private final int bitSize;
	private final int declSize;

	BcpiBitField(BitFieldDataType type) {
		super(type);
		this.wrapped = BcpiType.from(type.getBaseDataType());
		this.bitSize = type.getBitSize();
		this.declSize = type.getDeclaredBitSize();
	}

	/**
	 * Convert a Ghidra type to a BcpiBitField.
	 */
	public static BcpiBitField from(BitFieldDataType type) {
		return (BcpiBitField)BcpiType.from(type);
	}

	@Override
	public BitFieldDataType toGhidra() {
		return (BitFieldDataType)super.toGhidra();
	}

	@Override
	public BcpiType unwrap() {
		return this.wrapped;
	}

	@Override
	public int getByteSize() {
		return (this.bitSize + 7) / 8;
	}

	@Override
	public int getBitSize() {
		return this.bitSize;
	}

	@Override
	public void toC(StringBuilder specifier, StringBuilder prefix, StringBuilder suffix) {
		suffix.append(" : ").append(this.declSize);
		this.wrapped.toC(specifier, prefix, suffix);
	}
}
