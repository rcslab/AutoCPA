package bcpi.type;

import ghidra.program.model.data.Enum;

/**
 * BCPI enum type.
 */
public final class BcpiEnum extends AbstractType {
	BcpiEnum(Enum type) {
		super(type);
	}

	/**
	 * Convert a Ghidra type to a BcpiEnum.
	 */
	public static BcpiEnum from(Enum type) {
		return (BcpiEnum)BcpiType.from(type);
	}

	@Override
	public Enum toGhidra() {
		return (Enum)super.toGhidra();
	}

	@Override
	public void toC(StringBuilder specifier, StringBuilder prefix, StringBuilder suffix) {
		specifier.append("enum ");

		var name = getName();
		if (name.startsWith("anon_enum_")) {
			specifier.append("{ ... }");
		} else {
			specifier.append(name);
		}
	}
}
