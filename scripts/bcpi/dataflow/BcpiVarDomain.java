package bcpi.dataflow;

import ghidra.program.model.data.DataType;
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
 * The BCPI varnode abstract domain.
 */
public class BcpiVarDomain implements SparseDomain<BcpiVarDomain, BcpiVarDomain> {
	private final PtrDomain ptrFacts;
	private final IntDomain intFacts;

	private BcpiVarDomain(PtrDomain ptrFacts, IntDomain intFacts) {
		this.ptrFacts = ptrFacts;
		this.intFacts = intFacts;
	}

	/**
	 * @return The bottom lattice element.
	 */
	public static BcpiVarDomain bottom() {
		return new BcpiVarDomain(PtrDomain.bottom(), IntDomain.bottom());
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
	public static BcpiVarDomain top() {
		return new BcpiVarDomain(PtrDomain.top(), IntDomain.top());
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
	public BcpiVarDomain copy() {
		return new BcpiVarDomain(
			this.ptrFacts.copy(),
			this.intFacts.copy());
	}

	@Override
	public boolean joinInPlace(BcpiVarDomain other) {
		return this.ptrFacts.joinInPlace(other.ptrFacts)
			| this.intFacts.joinInPlace(other.intFacts);
	}

	@Override
	public BcpiVarDomain getDefault(Varnode vn) {
		return new BcpiVarDomain(
			PtrDomain.bottom().getDefault(vn),
			IntDomain.bottom().getDefault(vn));
	}

	@Override
	public boolean supports(PcodeOp op) {
		return this.ptrFacts.supports(op) || this.intFacts.supports(op);
	}

	@Override
	public BcpiVarDomain visit(PcodeOp op, VarMap<BcpiVarDomain> map) {
		var ptrFacts = this.ptrFacts.visit(op, map);
		var intFacts = this.intFacts.visit(op, map.andThen(BcpiVarDomain::getIntFacts));
		return new BcpiVarDomain(ptrFacts, intFacts);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof BcpiVarDomain)) {
			return false;
		}

		var other = (BcpiVarDomain) obj;
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
