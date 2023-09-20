package bcpi.type;

import ghidra.program.model.data.Union;

/**
 * BCPI union type.
 */
public final class BcpiUnion extends AbstractAggregate {
	BcpiUnion(Union type) {
		super(type);
	}

	/**
	 * Convert a Ghidra type to a BcpiUnion.
	 */
	public static BcpiUnion from(Union type) {
		return (BcpiUnion)BcpiType.from(type);
	}

	@Override
	public Union toGhidra() {
		return (Union)super.toGhidra();
	}

	@Override
	public void toC(StringBuilder specifier, StringBuilder prefix, StringBuilder suffix) {
		specifier.append("union ");

		var name = getName();
		if (name.startsWith("anon_union_")) {
			specifier.append("{ ... }");
		} else {
			specifier.append(name);
		}
	}
}
