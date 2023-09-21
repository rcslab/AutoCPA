package bcpi.type;

import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * BCPI bit-field type.
 */
public final class BcpiFunctionType extends AbstractType {
	private final BcpiType retType;
	private final List<BcpiType> paramTypes;

	BcpiFunctionType(FunctionDefinition type) {
		super(type);
		this.retType = BcpiType.from(type.getReturnType());
		this.paramTypes = Arrays.stream(type.getArguments())
			.map(ParameterDefinition::getDataType)
			.map(BcpiType::from)
			.collect(Collectors.toUnmodifiableList());
	}

	/**
	 * Convert a Ghidra type to a BcpiFunctionType.
	 */
	public static BcpiFunctionType from(FunctionDefinition type) {
		return (BcpiFunctionType)BcpiType.from(type);
	}

	@Override
	public FunctionDefinition toGhidra() {
		return (FunctionDefinition)super.toGhidra();
	}

	/**
	 * @return The return type.
	 */
	public BcpiType getReturnType() {
		return this.retType;
	}

	@Override
	public BcpiType unwrap() {
		return this.retType;
	}

	/**
	 * @return The parameter types.
	 */
	public List<BcpiType> getParamTypes() {
		return this.paramTypes;
	}

	@Override
	public void toC(StringBuilder specifier, StringBuilder prefix, StringBuilder suffix) {
		suffix.append(this.paramTypes
			.stream()
			.map(BcpiType::toC)
			.collect(Collectors.joining(", ", "(", ")")));

		this.retType.toC(specifier, prefix, suffix);
	}
}
