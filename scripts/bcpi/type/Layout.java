package bcpi.type;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Memory layouts for aggregates.
 */
public final class Layout {
	private int size;
	private int maxDepth;
	private final int align;
	private final List<Field> fields;

	Layout(int align, List<Field> fields) {
		this.align = align;
		this.fields = fields;

		this.size = 0;
		updateSize();

		this.maxDepth = 0;
		for (var field : fields) {
			this.maxDepth = Math.max(this.maxDepth, field.getType().getAggregateDepth());
		}
	}

	/**
	 * Round down to a multiple of an alignment.
	 */
	private static int alignFloor(int offset, int align) {
		assert (align & (align - 1)) == 0;
		return offset & ~(align - 1);
	}

	/**
	 * Round up to a multiple of an alignment.
	 */
	private static int alignCeil(int offset, int align) {
		return alignFloor(offset + align - 1, align);
	}

	/**
	 * @return The size of this layout, in bytes.
	 */
	public int getByteSize() {
		return this.size;
	}

	/**
	 * @return The required alignment for this layout, in bytes.
	 */
	public int getByteAlignment() {
		return this.align;
	}

	/**
	 * @return The fields of this layout.
	 */
	public List<Field> getFields() {
		return Collections.unmodifiableList(this.fields);
	}

	/**
	 * @return The numbre of internal padding bytes in this layout.
	 */
	public int getInternalPaddingBytes() {
		int padding = 0;
		int lastEnd = 0;
		for (var field : this.fields) {
			padding += Math.max(0, field.getStartByte() - lastEnd);
			lastEnd = field.getEndByte();
		}
		return padding;
	}

	/**
	 * @return An empty, mutable copy of this layout.
	 */
	public Layout emptyCopy() {
		return prefix(0);
	}

	/**
	 * @return A mutable copy of this layout with only the first n fields.
	 */
	public Layout prefix(int n) {
		return new Layout(this.align, new ArrayList<>(this.fields.subList(0, n)));
	}

	/**
	 * Append a field to this layout.
	 */
	public void add(Field field) {
		int startBit = 0;
		int bitSize = field.getBitSize();

		int i = this.fields.size();
		if (i > 0) {
			startBit = this.fields.get(i - 1).getEndBit();
		}

		var type = field.getType();
		if (type instanceof BcpiBitField) {
			var baseType = type.unwrap();
			int nextOffset = alignCeil(startBit, baseType.getBitAlignment());
			if (startBit + bitSize > nextOffset) {
				startBit = nextOffset;
			}
		} else {
			startBit = alignCeil(startBit, type.getBitAlignment());
		}

		this.fields.add(field.reorder(startBit, i));
		updateSize();
	}

	private void updateSize() {
		int i = this.fields.size();
		if (i > 0) {
			var lastField = this.fields.get(i - 1);
			this.size = alignCeil(lastField.getEndByte(), this.align);
			this.maxDepth = Math.max(this.maxDepth, lastField.getType().getAggregateDepth());
		}
	}

	/**
	 * @return The maximum aggregate nesting depth of this layout, i.e. how many layers of
	 *         struct { union { struct { ... }}} there are.
	 */
	public int getAggregateDepth() {
		return 1 + this.maxDepth;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (obj instanceof Layout other) {
			return this.size == other.size
				&& this.align == other.align
				&& this.fields.equals(other.fields);
		} else {
			return false;
		}
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.size, this.align, this.fields);
	}

	@Override
	public String toString() {
		return this.fields
			.stream()
			.map(Field::toString)
			.collect(Collectors.joining("\n"));
	}
}
