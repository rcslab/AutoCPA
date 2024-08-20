package bcpi.dataflow;

import bcpi.type.BcpiAggregate;
import bcpi.type.BcpiArray;
import bcpi.type.BcpiPrimitive;
import bcpi.type.BcpiType;

import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.stream.Collectors;

/**
 * The abstract domain for pointer varnodes.
 */
public class PtrDomain implements Lattice<PtrDomain> {
	/** The type of the outermost known allocation we point to. */
	private Flattice<BcpiType> type;
	/** The offset from the base of the outer allocation. */
	private IntDomain offset;
	/** Whether the allocation might be an array. */
	private boolean maybeArray;

	private PtrDomain(Flattice<BcpiType> type, IntDomain offset, boolean maybeArray) {
		this.type = type;
		this.offset = offset;
		this.maybeArray = maybeArray;
	}

	/**
	 * @return The bottom element of this lattice.
	 */
	public static PtrDomain bottom() {
		return new PtrDomain(Flattice.bottom(), IntDomain.bottom(), false);
	}

	/**
	 * @return Whether this is the bottom lattice element.
	 */
	public boolean isBottom() {
		return this.type.isBottom() && this.offset.isBottom() && !this.maybeArray;
	}

	/**
	 * @return The top element of this lattice.
	 */
	public static PtrDomain top() {
		return new PtrDomain(Flattice.top(), IntDomain.top(), true);
	}

	/**
	 * @return Whether this is the top lattice element.
	 */
	public boolean isTop() {
		return this.type.isTop() && this.offset.isTop() && this.maybeArray;
	}

	/**
	 * @return The type of the pointed-to allocation.
	 */
	public Optional<BcpiType> getType() {
		return this.type.get();
	}

	/**
	 * @return Whether the type is known.
	 */
	public boolean hasType() {
		return getType().isPresent();
	}

	/**
	 * @return The offset within the allocation.
	 */
	public OptionalInt getOffset() {
		var type = getType().orElse(null);
		if (type == null) {
			return OptionalInt.empty();
		}

		var wrapped = this.offset.mod(type.getByteSize());
		var offset = wrapped.getIfConstant();
		if (!offset.isPresent()) {
			return OptionalInt.empty();
		}

		return OptionalInt.of((int) offset.getAsLong());
	}

	/**
	 * @return Whether the offset is known.
	 */
	public boolean hasOffset() {
		return getOffset().isPresent();
	}

	/**
	 * @return A copy of these facts with an additional offset.
	 */
	public PtrDomain plusOffset(IntDomain offset) {
		return new PtrDomain(this.type.copy(), this.offset.add(offset), this.maybeArray);
	}

	/**
	 * @return A copy of these facts which might be an array.
	 */
	public PtrDomain asArray() {
		return new PtrDomain(this.type.copy(), this.offset.copy(), true);
	}

	/**
	 * @return Whether the allocation might be an array.
	 */
	public boolean isMaybeArray() {
		return this.maybeArray;
	}

	@Override
	public PtrDomain copy() {
		return new PtrDomain(this.type.copy(), this.offset.copy(), this.maybeArray);
	}

	/**
	 * Compare two types in the containment lattice.
	 */
	private static int compareTypes(BcpiType thisType, BcpiType otherType) {
		if (thisType.equals(otherType)) {
			return 0;
		}

		// Prefer more deeply-nested types, e.g. struct bar { struct foo foo; }
		// over struct foo
		var thisDepth = thisType.getAggregateDepth();
		var otherDepth = otherType.getAggregateDepth();
		if (thisDepth < otherDepth) {
			return -1;
		} else if (thisDepth > otherDepth) {
			return 1;
		}

		// Prefer larger types
		var thisSize = thisType.getBitSize();
		var otherSize = otherType.getBitSize();
		if (thisSize < otherSize) {
			return -1;
		} else if (thisSize > otherSize) {
			return 1;
		}

		if (thisDepth == 0) {
			// For non-aggregates, any arbitrary ordering will do.  We want to avoid
			// becoming ⊤ for as long as we can in case we get joined with an aggregate
			// later.  We also want the ordering to be stable between runs.
			var thisId = thisType.toGhidra().getUniversalID();
			var otherId = otherType.toGhidra().getUniversalID();
			if (thisId != null && otherId != null) {
				return Long.compare(thisId.getValue(), otherId.getValue());
			} else if (thisId != null) {
				return 1;
			} else if (otherId != null) {
				return -1;
			}

			return thisType.getName().compareTo(otherType.getName());
		}

		// At this point we have two same-sized, same-depth aggregates (and maybe a strict-
		// aliasing violation).  Neither one is "better" so give up for now.
		return 0;
	}

	@Override
	public boolean joinInPlace(PtrDomain other) {
		var ret = false;

		var prev = this.type.copy();

		int typeCmp = 0;
		if (this.hasType() && other.hasType()) {
			var thisType = this.getType().get();
			var otherType = other.getType().get();
			typeCmp = compareTypes(thisType, otherType);
		}

		if (typeCmp == 0) {
			ret |= this.type.joinInPlace(other.type);
			ret |= this.offset.joinInPlace(other.offset);
		} else if (typeCmp < 0) {
			this.type = other.type.copy();
			this.offset = other.offset.copy();
			ret = true;
		} else {
			// We are higher in the lattice, do nothing
		}

		if (!this.maybeArray && other.maybeArray) {
			this.maybeArray = true;
			ret = true;
		}

		return ret;
	}

	/**
	 * Resolve a type and decay arrays to their element type.
	 */
	private static BcpiType unwrapArray(BcpiType type) {
		while (type instanceof BcpiArray array) {
			type = array.unwrap().resolve();
		}
		return type;
	}

	public static PtrDomain initial(VarOp vop) {
		var vn = vop.getVar();

		var type = Optional
			.ofNullable(vn.getHigh())        // Get the high-level variable
			.map(HighVariable::getDataType)  // Get its type
			.map(BcpiType::from)             // Convert to BCPI
			.map(BcpiType::dereference)      // Dereference it
			.map(BcpiType::resolve);         // Resolve typedefs

		var isArray = type
			.filter(t -> t instanceof BcpiArray)
			.isPresent();
		type = type.map(PtrDomain::unwrapArray); // Unwrap array types

		var offset = type
			.map(t -> IntDomain.constant(0)) // If the type is known, the offset is zero
			.orElseGet(IntDomain::bottom);   // Otherwise, the offset is unknown

		return new PtrDomain(Flattice.ofOptional(type), offset, isArray);
	}

	public boolean supports(VarOp vop) {
		var op = vop.getOp();
		if (op == null) {
			return false;
		}

		switch (op.getOpcode()) {
			case PcodeOp.CAST:
			case PcodeOp.COPY:
			case PcodeOp.MULTIEQUAL:
			case PcodeOp.PTRADD:
			case PcodeOp.PTRSUB:
			case PcodeOp.INT_ADD:
			case PcodeOp.INT_SUB:
				return true;
			default:
				return false;
		}
	}

	private static PtrDomain getPtr(List<BcpiDomain> inputs, int i) {
		return inputs.get(i).getPtrFacts();
	}

	private static IntDomain getInt(List<BcpiDomain> inputs, int i) {
		return inputs.get(i).getIntFacts();
	}

	public PtrDomain visit(PcodeOp op, List<BcpiDomain> inputs) {
		PtrDomain out;
		switch (op.getOpcode()) {
			case PcodeOp.CAST:
			case PcodeOp.COPY:
				out = getPtr(inputs, 0).copy();
				break;

			case PcodeOp.MULTIEQUAL:
				// Phi node
				out = bottom();
				for (var input : inputs) {
					out.joinInPlace(input.getPtrFacts());
				}
				break;

			case PcodeOp.PTRADD: {
				// This operator serves as a more compact representation of the pointer
				// calculation, input0 + input1 * input2, but also indicates explicitly that
				// input0 is a reference to an array data-type.
				var array = getPtr(inputs, 0).asArray();
				var index = getInt(inputs, 1);
				var stride = getInt(inputs, 2);
				IntDomain offset = index.multiply(stride);
				out = array.plusOffset(offset);
				break;
			}

			case PcodeOp.PTRSUB: {
				// A PTRSUB performs the simple pointer calculation, input0 + input1, but
				// also indicates explicitly that input0 is a reference to a structured
				// data-type and one of its subcomponents is being accessed.
				var ptr = getPtr(inputs, 0);
				var offset = getInt(inputs, 1);
				out = ptr.plusOffset(offset);
				break;
			}

			case PcodeOp.INT_ADD: {
				// Not all pointer arithmetic becomes PTRSUB
				var ptr = getPtr(inputs, 0);
				var offset = getInt(inputs, 1);
				if (!ptr.hasType()) {
					// Could be offset + ptr
					ptr = getPtr(inputs, 1);
					offset = getInt(inputs, 0);
				}
				out = ptr.plusOffset(offset);
				break;
			}

			case PcodeOp.INT_SUB: {
				// Not all pointer arithmetic becomes PTRSUB
				var ptr = getPtr(inputs, 0);
				var offset = getInt(inputs, 1);
				out = ptr.plusOffset(offset.negate());
				break;
			}

			default:
				out = top();
				break;
		}

		if (!out.hasType()) {
			out = initial(new VarOp(op.getOutput(), op));
		}

		return out;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof PtrDomain)) {
			return false;
		}

		var other = (PtrDomain) obj;
		return this.type.equals(other.type)
			&& this.offset.equals(other.offset)
			&& this.maybeArray == other.maybeArray;
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.type, this.offset, this.maybeArray);
	}

	@Override
	public String toString() {
		if (isBottom()) {
			return "⊥";
		} else if (isTop()) {
			return "⊤";
		} else {
			String type = this.type.get()
				.map(BcpiType::toC)
				.orElseGet(this.type::toString);
			String array = this.maybeArray ? "[]" : "*";
			return String.format("{%s%s + %s}", type, array, this.offset);
		}
	}
}
