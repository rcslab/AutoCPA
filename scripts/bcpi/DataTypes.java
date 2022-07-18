package bcpi;

import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.util.Msg;

import com.google.common.base.Equivalence;
import com.google.common.base.Throwables;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Utilities for working with data types.
 */
public class DataTypes {
	private static final ConcurrentMap<DataTypePath, DataType> dedupMap = new ConcurrentHashMap<>();
	private static final Set<Equivalence.Wrapper<DataType>> dedupSeen = ConcurrentHashMap.newKeySet();

	/**
	 * Deduplicate a DataType.
	 */
	public static DataType dedup(DataType type) {
		DataType result = dedupMap.putIfAbsent(type.getDataTypePath(), type);
		if (result == null) {
			result = type;
		}

		if (result != type) {
			if (dedupSeen.add(Equivalence.identity().wrap(type))) {
				String fullName = type.getPathName();
				String source = type.getDataTypeManager().getName();
				String dest = result.getDataTypeManager().getName();
				String message = String.format("Deduplicating %s from %s to %s", fullName, source, dest);
				Msg.debug(DataTypes.class, message);
			}
		}

		return result;
	}

	/**
	 * Resolve any typedefs until reaching a concrete type.
	 */
	public static DataType resolve(DataType type) {
		if (type instanceof TypeDef) {
			return ((TypeDef) type).getBaseDataType();
		} else {
			return type;
		}
	}

	/**
	 * Dereference a pointer data type.
	 */
	public static Optional<DataType> dereference(DataType type) {
		return Optional.of(type)
			.map(DataTypes::resolve)
			.filter(t -> t instanceof Pointer)
			.map(t -> ((Pointer) t).getDataType());
	}

	/**
	 * Get the byte alignment of a structure.
	 */
	public static int getAlignment(Structure struct) {
		int align = struct.getAlignment();
		for (Field field : Field.allFields(struct)) {
			align = Math.max(align, field.getDataType().getAlignment());
		}
		return align;
	}

	/**
	 * Add a field to the end of a struct.
	 */
	public static void addField(Structure struct, DataTypeComponent field) {
		DataTypeComponent[] fields = struct.getDefinedComponents();

		if (field.isBitFieldComponent()) {
			BitFieldDataType bitField = (BitFieldDataType) field.getDataType();
			DataType baseType = bitField.getBaseDataType();

			int bitSize = bitField.getBitSize();
			int byteOffset = 0;
			int bitOffset = 0;

			if (fields.length > 0) {
				DataTypeComponent prev = fields[fields.length - 1];

				byteOffset = prev.getEndOffset() + 1;
				int align = baseType.getAlignment();
				int delta = byteOffset % align;
				if (delta >= 0) {
					byteOffset += align - delta;
				}

				// GCC/Clang bitfield packing algorithm: jump back to the *previous*
				// aligned offset for the base type, and pack there if there are
				// enough free bits; otherwise, use the next aligned offset
				if (byteOffset >= align) {
					int bitStart = 8 * (byteOffset - align);
					int bitEnd = bitStart + 8 * baseType.getLength();
					int bitFree = 8 * prev.getOffset();
					if (prev.isBitFieldComponent()) {
						BitFieldDataType prevBitField = (BitFieldDataType) prev.getDataType();
						bitFree += prevBitField.getBitOffset() + prevBitField.getBitSize();
					} else {
						bitFree += 8 * prev.getLength();
					}

					if (bitEnd - bitFree >= bitSize) {
						byteOffset = bitFree / 8;
						bitOffset = bitFree % 8;
					}
				}
			}

			int byteWidth = BitFieldDataType.getMinimumStorageSize(bitSize, bitOffset);

			try {
				struct.insertBitFieldAt(byteOffset, byteWidth, bitOffset, baseType, bitSize, field.getFieldName(), field.getComment());
			} catch (Exception e) {
				throw Throwables.propagate(e);
			}
		} else {
			int offset = 0;
			if (fields.length > 0) {
				DataTypeComponent prev = fields[fields.length - 1];
				offset = prev.getEndOffset() + 1;
			}

			DataType type = field.getDataType();
			int align = type.getAlignment();
			int delta = offset % align;
			if (delta > 0) {
				offset += align - delta;
			}

			struct.insertAtOffset(offset, type, field.getLength(), field.getFieldName(), field.getComment());
		}
	}
}
