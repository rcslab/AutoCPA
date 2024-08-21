package bcpi.type;

import bcpi.util.Lazy;

import ghidra.program.model.data.Composite;

import java.util.ArrayList;
import java.util.List;

/**
 * Base class for BCPI aggregate types.
 */
abstract class AbstractAggregate extends AbstractType implements BcpiAggregate {
	private final Lazy<Layout> layout = new Lazy<>(this::computeLayout);

	AbstractAggregate(Composite type) {
		super(type);
	}

	@Override
	public Composite toGhidra() {
		return (Composite)super.toGhidra();
	}

	@Override
	public int getByteSize() {
		// Ghidra thinks empty structs have size 1, but we want them to
		// have size 0
		return getLayout().getByteSize();
	}

	@Override
	public int getByteAlignment() {
		// Ghidra sometimes underestimates aggregate alignment, so
		// compute it ourselves
		return getLayout().getByteAlignment();
	}

	@Override
	public Layout getLayout() {
		return this.layout.get();
	}

	private Layout computeLayout() {
		var type = (Composite)toGhidra();
		int align = type.getAlignment();
		var fields = new ArrayList<Field>();
		for (var comp : type.getDefinedComponents()) {
			var field = Field.from(comp, this, fields.size());
			fields.add(field);
			align = Math.max(align, field.getType().getByteAlignment());
		}
		return new Layout(align, List.copyOf(fields));
	}
}
