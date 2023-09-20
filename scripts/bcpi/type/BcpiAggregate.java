package bcpi.type;

import ghidra.program.model.data.Composite;

import java.util.List;

/**
 * BCPI aggregate (struct/union) types.
 */
public interface BcpiAggregate extends BcpiType {
	/**
	 * Convert a Ghidra composite to a BcpiAggregate.
	 */
	static BcpiAggregate from(Composite type) {
		return (BcpiAggregate)BcpiType.from(type);
	}

	@Override
	Composite toGhidra();

	/**
	 * @return The memory layout of this type.
	 */
	Layout getLayout();

	/**
	 * @return The fields of this type.
	 */
	default List<Field> getFields() {
		return getLayout().getFields();
	}
}
