package bcpi;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.util.Msg;

import com.google.common.base.Equivalence;
import com.google.common.base.Throwables;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

/**
 * Utilities for working with data types.
 */
public class DataTypes {
	private static final ConcurrentMap<DataTypePath, DataType> dedupMap = new ConcurrentHashMap<>();
	private static final Set<Equivalence.Wrapper<DataType>> dedupSeen = ConcurrentHashMap.newKeySet();

	/**
	 * Check if two data types are the same.
	 */
	public static boolean areEqual(DataType type, DataType other) {
		return type.getDataTypePath().equals(other.getDataTypePath());
	}

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
	 * Get the fields of an composite type within a memory range.
	 */
	public static List<Field> getFieldsBetween(DataType type, int offset, int endOffset) {
		List<Field> fields = new ArrayList<>();
		collectFieldsBetween(type, offset, endOffset, fields);
		return fields;
	}

	private static void collectFieldsBetween(DataType type, int offset, int endOffset, List<Field> fields) {
		type = resolve(type);

		if (type instanceof Structure) {
			Structure struct = (Structure) dedup(type);
			for (Field field : Field.allFields(struct)) {
				int pos = field.getOffset();
				int start = Math.max(offset, field.getOffset()) - pos;
				int end = Math.min(endOffset, field.getEndOffset()) - pos;
				if (start < end) {
					fields.add(field);
					collectFieldsBetween(field.getDataType(), start, end, fields);
				}
			}
		}
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

	/**
	 * Create an empty structure that's otherwise a copy of the given structure.
	 */
	public static Structure emptyStructLike(Structure struct) {
		return new StructureDataType(struct.getCategoryPath(), struct.getName(), 0, struct.getDataTypeManager());
	}

	/**
	 * Pad the tail of a structure to the given alignment.
	 */
	public static void padTail(Structure struct, int align) {
		int slop = align - (struct.getLength() % align);
		if (slop != align) {
			struct.add(DefaultDataType.dataType, slop);
		}
	}

	/**
	 * Unwrap any arrays, pointers, etc. from a type.
	 */
	public static DataType undecorate(DataType type) {
		while (true) {
			if (type instanceof Array) {
				type = ((Array) type).getDataType();
			} else if (type instanceof BitFieldDataType) {
				type = ((BitFieldDataType) type).getBaseDataType();
			} else if (type instanceof FunctionDefinition) {
				type = ((FunctionDefinition) type).getReturnType();
			} else if (type instanceof Pointer) {
				type = ((Pointer) type).getDataType();
			} else {
				break;
			}
		}

		return type;
	}

	/**
	 * Format a C type.
	 */
	public static String formatCDecl(DataType type) {
		return formatCDecl(type, "");
	}

	/**
	 * Format a C declaration.
	 */
	public static String formatCDecl(DataType type, String name) {
		StringBuilder spec = new StringBuilder();
		StringBuilder decl = new StringBuilder();
		formatCDecl(type, name, spec, decl);

		if (decl.length() > 0) {
			spec.append(" ").append(decl);
		}

		return spec.toString();
	}

	/**
	 * Format a C declaration into a separate specifier and declarator.
	 */
	public static void formatCDecl(DataType type, String name, StringBuilder specifier, StringBuilder declarator) {
		declarator.append(name);

		while (true) {
			if (type instanceof Array) {
				Array array = (Array) type;
				type = array.getDataType();
				declarator
					.append("[")
					.append(array.getNumElements())
					.append("]");
			} else if (type instanceof BitFieldDataType) {
				BitFieldDataType bitField = (BitFieldDataType) type;
				type = bitField.getBaseDataType();
				declarator
					.append(" : ")
					.append(bitField.getDeclaredBitSize());
			} else if (type instanceof FunctionDefinition) {
				FunctionDefinition func = (FunctionDefinition) type;
				type = func.getReturnType();

				declarator.append(Arrays.stream(func.getArguments())
					.map(p -> formatCDecl(p.getDataType()))
					.collect(Collectors.joining(", ", "(", ")")));
			} else if (type instanceof Pointer) {
				type = ((Pointer) type).getDataType();

				if (type instanceof Array || type instanceof FunctionDefinition) {
					declarator
						.insert(0, "(*")
						.append(")");
				} else {
					declarator.insert(0, "*");
				}
			} else {
				break;
			}
		}

		String typeName = type.getName();
		if (typeName.endsWith(DataType.CONFLICT_SUFFIX)) {
			typeName = typeName.substring(0, typeName.length() - DataType.CONFLICT_SUFFIX.length());
		}

		if (type instanceof Enum) {
			specifier.append("enum ");

			if (typeName.startsWith("anon_enum_")) {
				specifier.append("{ ... }");
			} else {
				specifier.append(typeName);
			}
		} else if (type instanceof Structure) {
			specifier.append("struct ");

			if (typeName.startsWith("anon_struct_")) {
				specifier.append("{ ... }");
			} else {
				specifier.append(typeName);
			}
		} else if (type instanceof Union) {
			specifier.append("union ");

			if (typeName.startsWith("anon_union_")) {
				specifier.append("{ ... }");
			} else {
				specifier.append(typeName);
			}
		} else if (typeName.startsWith("anon_subr_")) {
			specifier.append("...");
			declarator
				.insert(0, "(*")
				.append(")(...)");
		} else {
			specifier.append(typeName);
		}
	}
}
