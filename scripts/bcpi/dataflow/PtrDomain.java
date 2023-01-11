package bcpi.dataflow;

import bcpi.DataTypes;

import ghidra.program.model.data.DataType;
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
public class PtrDomain implements SparseDomain<PtrDomain, BcpiVarDomain> {
	/** The type of the outermost known allocation we point to. */
	private final Flattice<DataType> type;
	/** The offset from the base of the outer allocation. */
	private final IntDomain offset;
	/** Whether the allocation might be an array. */
	private boolean maybeArray;

	private PtrDomain(Flattice<DataType> type, IntDomain offset, boolean maybeArray) {
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
	public Optional<DataType> getType() {
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

		var length = IntDomain.constant(type.getLength());
		var wrapped = this.offset.mod(length);
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

	@Override
	public boolean joinInPlace(PtrDomain other) {
		var ret = false;

		ret |= this.type.joinInPlace(other.type);
		ret |= this.offset.joinInPlace(other.offset);

		if (!this.maybeArray && other.maybeArray) {
			this.maybeArray = true;
			ret = true;
		}

		return ret;
	}

	@Override
	public PtrDomain getDefault(Varnode vn) {
		var type = Optional
			.ofNullable(vn.getHigh())        // Get the high-level variable
			.map(HighVariable::getDataType)  // Get its type
			.flatMap(DataTypes::dereference) // Dereference it
			.map(DataTypes::resolve)         // Resolve typedefs
			.map(DataTypes::dedup)           // Deduplicate it
			.map(Flattice::of)               // Wrap in a lattice
			.orElseGet(Flattice::bottom);    // Fall back to the bottom element

		var offset = type.get()
			.map(t -> IntDomain.constant(0)) // If the type is known, the offset is zero
			.orElseGet(IntDomain::bottom);   // Otherwise, the offset is unknown

		return new PtrDomain(type, offset, false);
	}

	@Override
	public boolean supports(PcodeOp op) {
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

	@Override
	public PtrDomain visit(PcodeOp op, VarMap<BcpiVarDomain> map) {
		VarMap<PtrDomain> ptrs = map.andThen(BcpiVarDomain::getPtrFacts);
		VarMap<IntDomain> ints = map.andThen(BcpiVarDomain::getIntFacts);

		PtrDomain out;
		switch (op.getOpcode()) {
			case PcodeOp.CAST:
			case PcodeOp.COPY:
				out = ptrs.getInput(op, 0);
				break;

			case PcodeOp.MULTIEQUAL:
				// Phi node
				out = bottom().join(ptrs.getInputs(op));
				break;

			case PcodeOp.PTRADD: {
				// This operator serves as a more compact representation of the pointer
				// calculation, input0 + input1 * input2, but also indicates explicitly that
				// input0 is a reference to an array data-type.
				var array = ptrs.getInput(op, 0).asArray();
				var index = ints.getInput(op, 1);
				var stride = ints.getInput(op, 2);
				IntDomain offset = index.multiply(stride);
				out = array.plusOffset(offset);
				break;
			}

			case PcodeOp.PTRSUB: {
				// A PTRSUB performs the simple pointer calculation, input0 + input1, but
				// also indicates explicitly that input0 is a reference to a structured
				// data-type and one of its subcomponents is being accessed.
				var ptr = ptrs.getInput(op, 0);
				var offset = ints.getInput(op, 1);
				out = ptr.plusOffset(offset);
				break;
			}

			case PcodeOp.INT_ADD: {
				// Not all pointer arithmetic becomes PTRSUB
				var ptr = ptrs.getInput(op, 0);
				var offset = ints.getInput(op, 1);
				if (!ptr.hasType()) {
					// Could be offset + ptr
					ptr = ptrs.getInput(op, 1);
					offset = ints.getInput(op, 0);
				}
				out = ptr.plusOffset(offset);
				break;
			}

			case PcodeOp.INT_SUB: {
				// Not all pointer arithmetic becomes PTRSUB
				var ptr = ptrs.getInput(op, 0);
				var offset = ints.getInput(op, 1);
				out = ptr.plusOffset(offset.negate());
				break;
			}

			default:
				out = top();
				break;
		}

		if (!out.hasType()) {
			out = getDefault(op.getOutput());
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
				.map(DataTypes::formatCDecl)
				.orElseGet(this.type::toString);
			String array = this.maybeArray ? "[]" : "*";
			return String.format("{%s%s + %s}", type, array, this.offset);
		}
	}
}
