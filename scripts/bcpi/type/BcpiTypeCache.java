package bcpi.type;

import bcpi.util.Cache;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.pcode.PartialUnion;

import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Cached BCPI type conversions.
 */
class BcpiTypeCache {
	/**
	 * Shallow reference equality for Ghidra types.
	 */
	private static final class ShallowKey {
		final DataType type;

		ShallowKey(DataType type) {
			this.type = type;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == this) {
				return true;
			} else if (obj instanceof ShallowKey other) {
				return this.type == other.type;
			} else {
				return false;
			}
		}

		@Override
		public int hashCode() {
			return System.identityHashCode(this.type);
		}
	}

	/** Global cache of data types known to be equivalent. */
	static final Cache<ShallowKey, Set<ShallowKey>> EQ_CACHE = new Cache<>(k -> ConcurrentHashMap.newKeySet());

	/**
	 * Normalize a data type path for deep equality checking.  The
	 * normalized path is used as a quick hash key such that two data types
	 * with different normalized paths are never considered equivalent.
	 */
	private static String normalizePath(DataType type) {
		var ret = type.getDataTypePath().getPath();

		// The user-defined type foo::bar will have a category path like
		// "/DWARF/header.h/foo".  But sometimes (e.g. with forward
		// declarations), it might be "/DWARF/_UNCATEGORIZED_/foo"
		// instead.  Allow these types to be de-duplicated by stripping
		// the filename from the category path.
		ret = ret.replaceFirst("^/DWARF/[^/]*/", "/DWARF/");

		// Whenever GHIDRA fails to merge two data types with the same
		// name, it appends .conflict, .conflict1, .conflict2, etc.
		// Strip this off so we can unify them if possible.
		ret = ret.replaceAll("\\.conflict[0-9]*", "");

		return ret;
	}

	/**
	 * Structural equality checker.
	 */
	private static final class DeepEq {
		/** Local cache of known equivalences. */
		private final Map<ShallowKey, Set<ShallowKey>> cache = new HashMap<>();
		private final ArrayDeque<DataType> todoA = new ArrayDeque<>();
		private final ArrayDeque<DataType> todoB = new ArrayDeque<>();

		/**
		 * @return Whether a and b are structurally equivalent.
		 */
		boolean check(DataType a, DataType b) {
			if (!pushCheck(a, b)) {
				return false;
			}

			while (!this.todoA.isEmpty()) {
				a = this.todoA.removeFirst();
				b = this.todoB.removeFirst();
				if (!checkNext(a, b)) {
					return false;
				}
			}

			// Promote the local cache to the global one if we succeeded
			cache.forEach((k, v) -> EQ_CACHE.get(k).addAll(v));
			return true;
		}

		private boolean checkNext(DataType a, DataType b) {
			var aKey = new ShallowKey(a);
			var bKey = new ShallowKey(b);
			var aEq = this.cache.computeIfAbsent(aKey, k -> new HashSet<>());
			var bEq = this.cache.computeIfAbsent(bKey, k -> new HashSet<>());
			// Co-induction: next check(a, b) call should return true
			if (!aEq.add(bKey)) {
				// Already known to be equal
				return true;
			}
			bEq.add(aKey);

			if (a instanceof Array aa) {
				return (b instanceof Array bb) && checkArray(aa, bb);
			} else if (a instanceof BitFieldDataType aa) {
				return (b instanceof BitFieldDataType bb) && checkBitField(aa, bb);
			} else if (a instanceof FunctionDefinition aa) {
				return (b instanceof FunctionDefinition bb) && checkFunction(aa, bb);
			} else if (a instanceof PartialUnion aa) {
				return (b instanceof PartialUnion bb) && checkPartialUnion(aa, bb);
			} else if (a instanceof Pointer aa) {
				return (b instanceof Pointer bb) && checkPointer(aa, bb);
			} else if (a instanceof Structure aa) {
				return (b instanceof Structure bb) && checkComposite(aa, bb);
			} else if (a instanceof TypeDef aa) {
				return (b instanceof TypeDef bb) && checkTypeDef(aa, bb);
			} else if (a instanceof Union aa) {
				return (b instanceof Union bb) && checkComposite(aa, bb);
			} else {
				return true;
			}
		}

		private boolean checkArray(Array a, Array b) {
			if (a.getNumElements() != b.getNumElements()) {
				return false;
			}
			return pushCheck(a.getDataType(), b.getDataType());
		}

		private boolean checkBitField(BitFieldDataType a, BitFieldDataType b) {
			if (a.getDeclaredBitSize() != b.getDeclaredBitSize()) {
				return false;
			}
			if (a.getBitOffset() != b.getBitOffset()) {
				return false;
			}
			return pushCheck(a.getBaseDataType(), b.getBaseDataType());
		}

		private boolean checkPointer(Pointer a, Pointer b) {
			return pushCheck(a.getDataType(), b.getDataType());
		}

		private boolean checkFunction(FunctionDefinition a, FunctionDefinition b) {
			var aParams = a.getArguments();
			var bParams = b.getArguments();
			if (aParams.length != bParams.length) {
				return false;
			}

			if (!pushCheck(a.getReturnType(), b.getReturnType())) {
				return false;
			}

			for (int i = 0; i < aParams.length; ++i) {
				var ap = aParams[i].getDataType();
				var bp = bParams[i].getDataType();
				if (!pushCheck(ap, bp)) {
					return false;
				}
			}

			return true;
		}

		private boolean checkComposite(Composite a, Composite b) {
			var aFields = a.getDefinedComponents();
			var bFields = b.getDefinedComponents();
			if (aFields.length != bFields.length) {
				return false;
			}

			for (int i = 0; i < aFields.length; ++i) {
				var af = aFields[i];
				var bf = bFields[i];
				if (af.getOffset() != bf.getOffset()) {
					return false;
				}
				if (!pushCheck(af.getDataType(), bf.getDataType())) {
					return false;
				}
			}

			return true;
		}

		private boolean checkTypeDef(TypeDef a, TypeDef b) {
			return pushCheck(a.getBaseDataType(), b.getBaseDataType());
		}

		private boolean checkPartialUnion(PartialUnion a, PartialUnion b) {
			return a.equals(b);
		}

		private boolean pushCheck(DataType a, DataType b) {
			if (a == b) {
				return true;
			} else if (a.getLength() != b.getLength()) {
				return false;
			}

			var aPath = normalizePath(a);
			var bPath = normalizePath(b);
			if (!aPath.equals(bPath)) {
				return false;
			}

			var aKey = new ShallowKey(a);
			var bKey = new ShallowKey(b);
			if (EQ_CACHE.get(aKey).contains(bKey)) {
				return true;
			}
			if (this.cache.getOrDefault(aKey, Set.of()).contains(bKey)) {
				return true;
			}

			this.todoA.addLast(a);
			this.todoB.addLast(b);
			return true;
		}
	}

	/**
	 * Deep structural equality for Ghidra types.
	 */
	private static final class DeepKey {
		final DataType type;
		final String path;

		DeepKey(DataType type) {
			this.type = type;
			this.path = normalizePath(type);
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == this) {
				return true;
			} else if (obj instanceof DeepKey other) {
				return new DeepEq().check(this.type, other.type);
			} else {
				return false;
			}
		}

		@Override
		public int hashCode() {
			return this.path.hashCode();
		}
	}

	private static final Cache<ShallowKey, BcpiType> SHALLOW_CACHE = new Cache<>(BcpiTypeCache::shallowMiss);
	private static final Cache<DeepKey, BcpiType> DEEP_CACHE = new Cache<>(BcpiTypeCache::deepMiss);

	/**
	 * @return The cached BcpiType for this Ghidra type.
	 */
	static BcpiType get(DataType type) {
		return SHALLOW_CACHE.get(new ShallowKey(type));
	}

	/**
	 * Search the deep-equivalence cache on a shallow miss.
	 */
	private static BcpiType shallowMiss(ShallowKey key) {
		return DEEP_CACHE.get(new DeepKey(key.type));
	}

	/**
	 * Convert a type on a deep cache miss.
	 */
	private static BcpiType deepMiss(DeepKey key) {
		var type = key.type;
		if (type instanceof Array t) {
			return new BcpiArray(t);
		} else if (type instanceof BitFieldDataType t) {
			return new BcpiBitField(t);
		} else if (type instanceof Enum t) {
			return new BcpiEnum(t);
		} else if (type instanceof FunctionDefinition t) {
			return new BcpiFunctionType(t);
		} else if (type instanceof Pointer t) {
			return new BcpiPointer(t);
		} else if (type instanceof Structure t) {
			return new BcpiStruct(t);
		} else if (type instanceof TypeDef t) {
			return new BcpiTypeDef(t);
		} else if (type instanceof Union t) {
			return new BcpiUnion(t);
		} else {
			return new BcpiPrimitive(type);
		}
	}
}
