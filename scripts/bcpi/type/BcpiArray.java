package bcpi.type;

import ghidra.program.model.data.Array;

/**
 * BCPI array type.
 */
public final class BcpiArray extends AbstractType {
	private final BcpiType wrapped;
	private final int count;

	BcpiArray(Array type) {
		super(type);
		this.wrapped = BcpiType.from(type.getDataType());
		this.count = type.getNumElements();
	}

	/**
	 * Convert a Ghidra type to a BcpiArray.
	 */
	public static BcpiArray from(Array type) {
		return (BcpiArray)BcpiType.from(type);
	}

	@Override
	public Array toGhidra() {
		return (Array)super.toGhidra();
	}

	@Override
	public BcpiType unwrap() {
		return this.wrapped;
	}

	@Override
	public int getByteSize() {
		// Ghidra thinks zero-length arrays are 1 byte long, but we want
		// them to be 0 bytes
		return this.count * this.wrapped.getByteSize();
	}

	/**
	 * @return The number of array elements.
	 */
	public int getCount() {
		return this.count;
	}

	@Override
	public void toC(StringBuilder specifier, StringBuilder prefix, StringBuilder suffix) {
		suffix.append("[")
			.append(this.count)
			.append("]");
		this.wrapped.toC(specifier, prefix, suffix);
	}
}
