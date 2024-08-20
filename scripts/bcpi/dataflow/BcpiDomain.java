package bcpi.dataflow;

import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.stream.Collectors;

/**
 * The BCPI abstract domain.
 */
public class BcpiDomain extends ForwardDomain<BcpiDomain> {
	private final PtrDomain ptrFacts;
	private final IntDomain intFacts;

	private BcpiDomain(PtrDomain ptrFacts, IntDomain intFacts) {
		this.ptrFacts = ptrFacts;
		this.intFacts = intFacts;
	}

	/**
	 * @return The bottom lattice element.
	 */
	public static BcpiDomain bottom() {
		return new BcpiDomain(PtrDomain.bottom(), IntDomain.bottom());
	}

	/**
	 * @return Whether this is the bottom lattice element.
	 */
	public boolean isBottom() {
		return this.ptrFacts.isBottom() && this.intFacts.isBottom();
	}

	/**
	 * @return The top lattice element.
	 */
	public static BcpiDomain top() {
		return new BcpiDomain(PtrDomain.top(), IntDomain.top());
	}

	/**
	 * @return Whether this is the top lattice element.
	 */
	public boolean isTop() {
		return this.ptrFacts.isTop() && this.intFacts.isTop();
	}

	/**
	 * @return The abstract value of this variable as a pointer.
	 */
	public PtrDomain getPtrFacts() {
		return this.ptrFacts;
	}

	/**
	 * @return The abstract value of this variable as an integer.
	 */
	public IntDomain getIntFacts() {
		return this.intFacts;
	}

	@Override
	public BcpiDomain copy() {
		return new BcpiDomain(
			this.ptrFacts.copy(),
			this.intFacts.copy());
	}

	@Override
	public boolean joinInPlace(BcpiDomain other) {
		return this.ptrFacts.joinInPlace(other.ptrFacts)
			| this.intFacts.joinInPlace(other.intFacts);
	}

	@Override
	public BcpiDomain initial(VarOp vop) {
		return new BcpiDomain(
			PtrDomain.initial(vop),
			IntDomain.initial(vop));
	}

	@Override
	public boolean supports(VarOp vop) {
		return this.ptrFacts.supports(vop) || this.intFacts.supports(vop);
	}

	@Override
	public boolean visit(VarOp vop, List<BcpiDomain> inputs) {
		var op = vop.getOp();
		if (op == null) {
			return false;
		}

		var ptrFacts = this.ptrFacts.visit(op, inputs);
		var intFacts = this.intFacts.visit(op, inputs);
		return this.ptrFacts.joinInPlace(ptrFacts)
			| this.intFacts.joinInPlace(intFacts);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof BcpiDomain)) {
			return false;
		}

		var other = (BcpiDomain) obj;
		return this.ptrFacts.equals(other.ptrFacts)
			&& this.intFacts.equals(other.intFacts);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.ptrFacts, this.intFacts);
	}

	@Override
	public String toString() {
		if (isBottom()) {
			return "⊥";
		} else if (isTop()) {
			return "⊤";
		} else {
			return String.format("{ptr: %s, int: %s}", this.ptrFacts, this.intFacts);
		}
	}
}
