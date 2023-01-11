package bcpi.dataflow;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.function.Function;

/**
 * The abstract domain for integer varnodes.
 */
public class IntDomain implements SparseDomain<IntDomain, IntDomain> {
	private final Flattice<Long> value;

	private IntDomain(Flattice<Long> value) {
		this.value = value;
	}

	/**
	 * @return The bottom element of this lattice.
	 */
	public static IntDomain bottom() {
		return new IntDomain(Flattice.bottom());
	}

	/**
	 * @return Whether this is the bottom lattice element.
	 */
	public boolean isBottom() {
		return this.value.isBottom();
	}

	/**
	 * @return The top element of this lattice.
	 */
	public static IntDomain top() {
		return new IntDomain(Flattice.top());
	}

	/**
	 * @return Whether this is the top lattice element.
	 */
	public boolean isTop() {
		return this.value.isTop();
	}

	/**
	 * @return An abstract value for a constant.
	 */
	public static IntDomain constant(long value) {
		return new IntDomain(Flattice.of(value));
	}

	/**
	 * @return Whether this abstract value is a constant.
	 */
	public boolean isConstant() {
		return this.value.isPresent();
	}

	/**
	 * @return The value of this integer, if it is constant.
	 */
	public OptionalLong getIfConstant() {
		return this.value
			.get()
			.map(OptionalLong::of)
			.orElseGet(OptionalLong::empty);
	}

	@Override
	public IntDomain copy() {
		return new IntDomain(this.value.copy());
	}

	@Override
	public boolean joinInPlace(IntDomain other) {
		return this.value.joinInPlace(other.value);
	}

	@Override
	public IntDomain getDefault(Varnode vn) {
		if (vn.isConstant()) {
			return constant(vn.getOffset());
		} else if (vn.getDef() == null) {
			// Parameters etc. can be anything
			return top();
		} else {
			// Locals start out uninitialized
			return bottom();
		}
	}

	@Override
	public boolean supports(PcodeOp op) {
		return false;
	}

	@Override
	public IntDomain visit(PcodeOp op, VarMap<IntDomain> map) {
		return top();
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.value);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof IntDomain)) {
			return false;
		}

		var other = (IntDomain) obj;
		return this.value.equals(other.value);
	}

	@Override
	public String toString() {
		return this.value.toString();
	}
}
