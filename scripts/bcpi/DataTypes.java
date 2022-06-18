package bcpi;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.util.Msg;

import com.google.common.base.Equivalence;

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
}
