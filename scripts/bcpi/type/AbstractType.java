package bcpi.type;

import ghidra.program.model.data.DataType;

/**
 * Base class for BCPI types.
 */
abstract class AbstractType implements BcpiType {
	private final DataType ghidra;
	private final String name;
	private final int size;
	private final int align;

	AbstractType(DataType ghidra) {
		this.ghidra = ghidra;

		var name = ghidra.getName();
		if (name.endsWith(DataType.CONFLICT_SUFFIX)) {
			name = name.substring(0, name.length() - DataType.CONFLICT_SUFFIX.length());
		}
		this.name = name;

		this.size = ghidra.getLength();
		this.align = ghidra.getAlignment();
	}

	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public int getByteSize() {
		return this.size;
	}

	@Override
	public int getByteAlignment() {
		return this.align;
	}

	@Override
	public DataType toGhidra() {
		return this.ghidra;
	}

	@Override
	public void toC(StringBuilder specifier, StringBuilder prefix, StringBuilder suffix) {
		specifier.append(getName());
	}

	@Override
	public String toString() {
		return toC();
	}
}
