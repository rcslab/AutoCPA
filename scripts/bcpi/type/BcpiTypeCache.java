package bcpi.type;

import bcpi.AnalysisContext;
import bcpi.util.Cache;
import bcpi.util.Log;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.BuiltInDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PartialUnion;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
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

		// Ignore the file that defined the path
		ret = ret.replaceFirst("^/DWARF/([^\\\\/]|\\\\/)*/", "/DWARF/");

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
		/** The two top-level types being compared. */
		private final DataType typeA;
		private final DataType typeB;
		/** Local cache of known equivalences. */
		private final Map<ShallowKey, Set<ShallowKey>> cache = new HashMap<>();
		/** Work lists. */
		private final ArrayDeque<DataType> todoA = new ArrayDeque<>();
		private final ArrayDeque<DataType> todoB = new ArrayDeque<>();

		DeepEq(DataType a, DataType b) {
			this.typeA = a;
			this.typeB = b;
		}

		/**
		 * @return Whether a and b are structurally equivalent.
		 */
		boolean check() {
			if (!pushCheck(this.typeA, this.typeB)) {
				return false;
			}

			while (!this.todoA.isEmpty()) {
				var a = this.todoA.removeFirst();
				var b = this.todoB.removeFirst();
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
				if (b instanceof Array bb) {
					return checkArray(aa, bb);
				}
			} else if (a instanceof BitFieldDataType aa) {
				if (b instanceof BitFieldDataType bb) {
					return checkBitField(aa, bb);
				}
			} else if (a instanceof Enum aa) {
				if (b instanceof Enum bb) {
					return checkEnum(aa, bb);
				}
			} else if (a instanceof FunctionDefinition aa) {
				if (b instanceof FunctionDefinition bb) {
					return checkFunction(aa, bb);
				}
			} else if (a instanceof PartialUnion aa) {
				if (b instanceof PartialUnion bb) {
					return checkPartialUnion(aa, bb);
				}
			} else if (a instanceof Pointer aa) {
				if (b instanceof Pointer bb) {
					return checkPointer(aa, bb);
				}
			} else if (a instanceof Structure aa) {
				if (b instanceof Structure bb) {
					return checkComposite(aa, bb);
				}
			} else if (a instanceof TypeDef aa) {
				if (b instanceof TypeDef bb) {
					return checkTypeDef(aa, bb);
				}
			} else if (a instanceof Union aa) {
				if (b instanceof Union bb) {
					return checkComposite(aa, bb);
				}
			} else if (a instanceof BuiltInDataType aa) {
				// Check this last because pointers can also be built-in
				if (b instanceof BuiltInDataType bb) {
					return checkBuiltIn(aa, bb);
				}
			} else {
				Log.trace("Don't know how to compare `%s` and `%s`", a.getClass().getSimpleName(), b.getClass().getSimpleName());
				return true;
			}

			return failure(a, b, "kind `%s` != `%s`", a.getClass().getSimpleName(), b.getClass().getSimpleName());
		}

		private boolean checkArray(Array a, Array b) {
			var aCount = a.getNumElements();
			var bCount = b.getNumElements();
			if (aCount != bCount) {
				return failure(a, b, "count %d != %d", aCount, bCount);
			}

			return pushCheck(a.getDataType(), b.getDataType());
		}

		private boolean checkBitField(BitFieldDataType a, BitFieldDataType b) {
			var aBits = a.getDeclaredBitSize();
			var bBits = b.getDeclaredBitSize();
			if (aBits != bBits) {
				return failure(a, b, "bit size %d != %d", aBits, bBits);
			}

			var aOffset = a.getBitOffset();
			var bOffset = b.getBitOffset();
			if (aOffset != bOffset) {
				return failure(a, b, "bit offset %d != %d", aOffset, bOffset);
			}

			return pushCheck(a.getBaseDataType(), b.getBaseDataType());
		}

		private boolean checkBuiltIn(BuiltInDataType a, BuiltInDataType b) {
			// We already know the name and size are the same
			return true;
		}

		private boolean checkEnum(Enum a, Enum b) {
			var aCount = a.getCount();
			var bCount = b.getCount();
			if (aCount != bCount) {
				return failure(a, b, "count %d != %d", aCount, bCount);
			}

			var aNames = a.getNames();
			var bNames = b.getNames();

			for (int i = 0; i < aCount; ++i) {
				if (!Objects.equals(aNames[i], bNames[i])) {
					return failure(a, b, "enumerator %d name `%s` != `%s`", aNames[i], bNames[i]);
				}

				var aValue = a.getValue(aNames[i]);
				var bValue = b.getValue(bNames[i]);
				if (aValue != bValue) {
					return failure(a, b, "enumerator `%s` value %d != %d", aNames[i], aValue, bValue);
				}
			}

			return true;
		}

		private boolean checkPointer(Pointer a, Pointer b) {
			return pushCheck(a.getDataType(), b.getDataType());
		}

		private boolean checkFunction(FunctionDefinition a, FunctionDefinition b) {
			var aParams = a.getArguments();
			var bParams = b.getArguments();
			if (aParams.length != bParams.length) {
				return failure(a, b, "parameter count %d != %d", aParams.length, bParams.length);
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
				return failure(a, b, "field count %d != %d", aFields.length, bFields.length);
			}

			for (int i = 0; i < aFields.length; ++i) {
				var af = aFields[i];
				var bf = bFields[i];
				if (af.getOffset() != bf.getOffset()) {
					return failure(a, b, "field %d offset %d != %d", i, af.getOffset(), bf.getOffset());
				}

				var afName = af.getFieldName();
				var bfName = bf.getFieldName();
				if (!Objects.equals(afName, bfName)) {
					return failure(a, b, "field %d name `%s`' != `%s`'", i, afName, bfName);
				}

				if (!pushCheck(af.getDataType(), bf.getDataType())) {
					return false;
				}
			}

			return true;
		}

		private boolean checkTypeDef(TypeDef a, TypeDef b) {
			return pushCheck(a.getDataType(), b.getDataType());
		}

		private boolean checkPartialUnion(PartialUnion a, PartialUnion b) {
			return a.equals(b);
		}

		private boolean pushCheck(DataType a, DataType b) {
			if (a == b) {
				return true;
			}

			a = canonicalize(a);
			b = canonicalize(b);
			if (a == b) {
				return true;
			}

			var aSize = a.getLength();
			var bSize = b.getLength();
			if (aSize != bSize) {
				return failure(a, b, "size %d != %d", aSize, bSize);
			}

			var aPath = normalizePath(a);
			var bPath = normalizePath(b);
			if (!aPath.equals(bPath)) {
				return failure(a, b, "qualified name `%s` != `%s`", aPath, bPath);
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

		/**
		 * Fail to unify two types (and possibly log a message).
		 */
		private boolean failure(DataType a, DataType b, String format, Object... args) {
			if (!Log.Level.TRACE.isEnabled()) {
				return false;
			}

			// Don't warn about partial unions
			if (this.typeA instanceof PartialUnion || this.typeB instanceof PartialUnion) {
				return false;
			}

			// Don't warn about bit-fields
			if (this.typeA instanceof BitFieldDataType || this.typeB instanceof BitFieldDataType) {
				return false;
			}

			var topA = new StringBuilder();
			var topB = new StringBuilder();
			describeTypes(this.typeA, this.typeB, topA, topB);

			var aStr = new StringBuilder();
			var bStr = new StringBuilder();
			describeTypes(a, b, aStr, bStr);

			Log.trace("Failed to unify `%s` and `%s`\n"
				  + "    because `%s` and `%s` are different\n"
				  + "    because %s\n",
				  topA, topB,
				  aStr, bStr,
				  String.format(format, args));

			return false;
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
				return new DeepEq(this.type, other.type).check();
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
	 * @return Whether a data type is incomplete (e.g. forward-declared).
	 */
	private static boolean isIncomplete(DataType type) {
		// Don't worry about pointers etc.
		if (!(type instanceof Composite)) {
			return false;
		}

		// Forward-declared types end up with a category path like
		// /DWARF/_UNCATEGORIZED_/foo
		var path = type.getDataTypePath().getCategoryPath().getPathElements();
		return path.length >= 2
			&& path[0].equals("DWARF")
			&& path[1].equals("_UNCATEGORIZED_");
	}

	/**
	 * Apply some pre-unification fixups to types.
	 */
	static DataType canonicalize(DataType type) {
		if (type == null) {
			Log.trace("Replacing null DataType with void");
			type = VoidDataType.dataType;
		}

		// Try to resolve forward-declared types to a complete definition
		if (isIncomplete(type)) {
			var name = type.getDataTypePath().getDataTypeName();
			var candidates = new ArrayList<DataType>();
			var dtm = type.getDataTypeManager();
			if (dtm != null) {
				dtm.findDataTypes(name, candidates);
			}
			candidates.removeIf(t -> isIncomplete(t));

			// If we couldn't find it in the same program, look in the rest
			if (candidates.isEmpty()) {
				var ctx = AnalysisContext.current();
				if (ctx != null) {
					for (var prog : ctx.getPrograms()) {
						prog.getDataTypeManager().findDataTypes(name, candidates);
					}
				}
			}
			candidates.removeIf(t -> isIncomplete(t));

			if (candidates.isEmpty()) {
				Log.trace("Could not resolve incomplete type `%s`", fullyQualifiedName(type));
			} else {
				if (Log.Level.TRACE.isEnabled()) {
					var before = new StringBuilder();
					var after = new StringBuilder();
					describeTypes(type, candidates.get(0), before, after);
					if (candidates.size() == 1) {
						Log.trace("Replacing `%s` with `%s`", before, after);
					} else {
						Log.trace("Replacing `%s` with `%s` (%d candidates)", before, after, candidates.size());
					}
				}
				type = candidates.get(0);
			}
		}

		return type;
	}

	/**
	 * Generate strings describing two Ghidra types, including any relevant differences.
	 */
	static void describeTypes(DataType a, DataType b, StringBuilder aStr, StringBuilder bStr) {
		var aProg = getProgram(a);
		var bProg = getProgram(b);
		if (!Objects.equals(aProg, bProg)) {
			// Show the originating program names, if different
			if (aProg != null) {
				aStr.append(aProg.getName()).append("::");
			}
			if (bProg != null) {
				bStr.append(bProg.getName()).append("::");
			}
		}

		var aPath = a.getDataTypePath();
		var bPath = b.getDataTypePath();

		var aCat = aPath.getCategoryPath();
		var bCat = bPath.getCategoryPath();
		for (var element : aCat.getPathElements()) {
			aStr.append(CategoryPath.unescapeString(element)).append("::");
		}
		if (aCat.equals(bCat)) {
			bStr.append("<...>::");
		} else {
			for (var element : bCat.getPathElements()) {
				bStr.append(CategoryPath.unescapeString(element)).append("::");
			}
		}

		aStr.append(aPath.getDataTypeName());
		bStr.append(bPath.getDataTypeName());
	}

	/**
	 * @return A human-readable fully-qualified type name.
	 */
	private static String fullyQualifiedName(DataType type) {
		var entries = new ArrayList<String>();

		var program = getProgram(type);
		if (program != null) {
			entries.add(program.getName());
		}

		for (var entry : type.getCategoryPath().getPathElements()) {
			entries.add(CategoryPath.unescapeString(entry));
		}

		entries.add(type.getDataTypePath().getDataTypeName());

		return String.join("::", entries);
	}

	/**
	 * @return The Program that defines a DataType, if any.
	 */
	private static Program getProgram(DataType type) {
		var manager = type.getDataTypeManager();
		if (manager instanceof ProgramBasedDataTypeManager pbdtm) {
			return pbdtm.getProgram();
		} else {
			return null;
		}
	}

	/**
	 * Search the deep-equivalence cache on a shallow miss.
	 */
	private static BcpiType shallowMiss(ShallowKey key) {
		var type = canonicalize(key.type);
		return DEEP_CACHE.get(new DeepKey(type));
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
