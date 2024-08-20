package bcpi.type;

import ghidra.program.model.data.DataType;

/**
 * BCPI's data type interface.
 */
public interface BcpiType {
	/**
	 * Convert a Ghidra type to a BcpiType.
	 */
	static BcpiType from(DataType type) {
		return BcpiTypeCache.get(type);
	}

	/**
	 * @return Ghidra's representation of this type.
	 */
	DataType toGhidra();

	/**
	 * @return The name of this type.
	 */
	String getName();

	/**
	 * @return The size (in bytes) of this type.
	 */
	int getByteSize();

	/**
	 * @return The size (in bits) of this type.
	 */
	default int getBitSize() {
		return 8 * getByteSize();
	}

	/**
	 * @return The required alignment (in bytes) of this type.
	 */
	int getByteAlignment();

	/**
	 * @return The required alignment (in bits) of this type.
	 */
	default int getBitAlignment() {
		return 8 * getByteAlignment();
	}

	/**
	 * Resolve any typedefs to their underlying type.
	 */
	default BcpiType resolve() {
		return this;
	}

	/**
	 * @return The wrapped type of an array/pointer/typedef/...
	 */
	default BcpiType unwrap() {
		return this;
	}

	/**
	 * @return The recursively unwrapped type.
	 */
	default BcpiType fullyUnwrap() {
		BcpiType next = this, ret;
		do {
			ret = next;
			next = next.unwrap();
		} while (ret != next);
		return ret;
	}

	/**
	 * @return The unwrapped type without following typedefs.
	 */
	default BcpiType undecorate() {
		return unwrap();
	}

	/**
	 * @return The recursively undecorated type.
	 */
	default BcpiType fullyUndecorate() {
		BcpiType next = this, ret;
		do {
			ret = next;
			next = next.undecorate();
		} while (ret != next);
		return ret;
	}

	/**
	 * @return The pointed-to type, or null if this is not a pointer.
	 */
	default BcpiType dereference() {
		return null;
	}

	/**
	 * @return The maximum aggregate nesting depth of this type, i.e. how many layers of
	 *         struct { union { struct { ... }}} there are.
	 */
	default int getAggregateDepth() {
		return 0;
	}

	/**
	 * Format this type as a C declaration.
	 */
	default String toC() {
		var spec = new StringBuilder();
		var prefix = new StringBuilder();
		var suffix = new StringBuilder();
		toC(spec, prefix, suffix);

		if (prefix.length() > 0) {
			spec.append(" ").append(prefix);
		}
		spec.append(suffix);
		return spec.toString();
	}

	/**
	 * Format this type as a C declaration.
	 *
	 * @param name
	 *         The name of the declared object.
	 */
	default String toC(String name) {
		var spec = new StringBuilder();
		var prefix = new StringBuilder();
		var suffix = new StringBuilder();
		toC(spec, prefix, suffix);
		return spec.append(" ")
			.append(prefix)
			.append(name)
			.append(suffix)
			.toString();
	}

	/**
	 * Format this type as a C declaration.
	 *
	 * @param name
	 *         The name of the declared object.
	 * @param specifier
	 *         The declaration-specifier (e.g. `struct foo`).
	 * @param declarator
	 *         The declarator (e.g. `*foo[42]`).
	 */
	default void toC(String name, StringBuilder specifier, StringBuilder declarator) {
		var prefix = new StringBuilder();
		var suffix = new StringBuilder();
		toC(specifier, prefix, suffix);

		declarator.append(prefix)
			.append(name)
			.append(suffix);
	}

	/**
	 * Format this type as a C declaration.
	 *
	 * @param name
	 *         The name of the declared object.
	 * @param specifier
	 *         The declaration-specifier (e.g. `struct foo`).
	 * @param prefix
	 *         The declarator prefix (e.g. `*`).
	 * @param suffiix
	 *         The declarator suffix (e.g. `[42]`).
	 */
	void toC(StringBuilder specifier, StringBuilder prefix, StringBuilder suffix);
}
