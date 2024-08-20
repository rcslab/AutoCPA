package bcpi.type;

import ghidra.program.model.data.TypeDef;

/**
 * BCPI bit-field type.
 */
public final class BcpiTypeDef extends AbstractType {
	private final BcpiType wrapped;
	private final BcpiType resolved;

	BcpiTypeDef(TypeDef type) {
		super(type);
		this.wrapped = BcpiType.from(type.getDataType());
		this.resolved = this.wrapped.resolve();
	}

	/**
	 * Convert a Ghidra type to a BcpiTypeDef.
	 */
	public static BcpiTypeDef from(TypeDef type) {
		return (BcpiTypeDef)BcpiType.from(type);
	}

	@Override
	public TypeDef toGhidra() {
		return (TypeDef)super.toGhidra();
	}

	@Override
	public BcpiType unwrap() {
		return this.wrapped;
	}

	@Override
	public BcpiType undecorate() {
		return this;
	}

	@Override
	public BcpiType resolve() {
		return this.resolved;
	}

	@Override
	public BcpiType dereference() {
		return this.resolved.dereference();
	}

	@Override
	public int getAggregateDepth() {
		return this.resolved.getAggregateDepth();
	}
}
