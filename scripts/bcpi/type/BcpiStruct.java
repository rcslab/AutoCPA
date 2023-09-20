package bcpi.type;

import ghidra.program.model.data.Structure;

/**
 * BCPI struct type.
 */
public final class BcpiStruct extends AbstractAggregate {
	BcpiStruct(Structure type) {
		super(type);
	}

	/**
	 * Convert a Ghidra type to a BcpiStruct.
	 */
	public static BcpiStruct from(Structure type) {
		return (BcpiStruct)BcpiType.from(type);
	}

	@Override
	public Structure toGhidra() {
		return (Structure)super.toGhidra();
	}

	@Override
	public void toC(StringBuilder specifier, StringBuilder prefix, StringBuilder suffix) {
		specifier.append("struct ");

		var name = getName();
		if (name.startsWith("anon_struct_")) {
			specifier.append("{ ... }");
		} else {
			specifier.append(name);
		}
	}
}
