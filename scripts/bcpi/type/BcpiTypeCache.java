package bcpi.type;

import bcpi.util.Cache;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypePath;

/**
 * Cached BCPI type conversions.
 */
class BcpiTypeCache {
	/**
	 * Cache key that de-duplicates DataTypes by path.
	 */
	private static final class DataTypeKey {
		final DataType type;

		DataTypeKey(DataType type) {
			this.type = type;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == this) {
				return true;
			} else if (!(obj instanceof DataTypeKey)) {
				return false;
			}

			var other = (DataTypeKey)obj;
			return this.type.getDataTypePath().equals(other.type.getDataTypePath());
		}

		@Override
		public int hashCode() {
			return this.type.getDataTypePath().hashCode();
		}
	}

	private static final Cache<DataTypeKey, BcpiType> CACHE = new Cache<>(BcpiTypeCache::compute);

	/**
	 * @return The cached BcpiType for this Ghidra type.
	 */
	static BcpiType get(DataType type) {
		return CACHE.get(new DataTypeKey(type));
	}

	private static BcpiType compute(DataTypeKey key) {
		var type = key.type;
		if (type instanceof Array t) {
			return new BcpiArray(t);
		} else if (type instanceof BitFieldDataType t) {
			return new BcpiBitField(t);
		} else {
			return new BcpiPrimitive(type);
		}
	}
}
