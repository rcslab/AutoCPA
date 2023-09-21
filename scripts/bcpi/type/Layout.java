package bcpi.type;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Memory layouts for aggregates.
 */
public final class Layout {
	private int size;
	private final int align;
	private final List<Field> fields;

	Layout(int size, int align, List<Field> fields) {
		this.size = size;
		this.align = align;
		this.fields = fields;
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
		return new Layout(0, this.align, new ArrayList<>(this.fields.subList(0, n)))
			.updateSize();
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

	private Layout updateSize() {
		int i = this.fields.size();
		if (i > 0) {
			this.size = alignCeil(this.fields.get(i - 1).getEndByte(), this.align);
		}
		return this;
	}
}
