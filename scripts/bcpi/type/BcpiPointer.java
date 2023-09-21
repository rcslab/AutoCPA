package bcpi.type;

import ghidra.program.model.data.Pointer;

/**
 * BCPI bit-field type.
 */
public final class BcpiPointer extends AbstractType {
	private final BcpiType wrapped;

	BcpiPointer(Pointer type) {
		super(type);
		this.wrapped = BcpiType.from(type.getDataType());
	}

	/**
	 * Convert a Ghidra type to a BcpiPointer.
	 */
	public static BcpiPointer from(Pointer type) {
		return (BcpiPointer)BcpiType.from(type);
	}

	@Override
	public Pointer toGhidra() {
		return (Pointer)super.toGhidra();
	}

	@Override
	public BcpiType unwrap() {
		return this.wrapped;
	}

	@Override
	public BcpiType dereference() {
		return this.wrapped;
	}

	@Override
	public void toC(StringBuilder specifier, StringBuilder prefix, StringBuilder suffix) {
		if (this.wrapped instanceof BcpiArray || this.wrapped instanceof BcpiFunctionType) {
			prefix.insert(0, "(*");
			suffix.append(")");
		} else {
			prefix.insert(0, "*");
		}

		this.wrapped.toC(specifier, prefix, suffix);
	}
}
