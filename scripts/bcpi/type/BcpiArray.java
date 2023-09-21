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
