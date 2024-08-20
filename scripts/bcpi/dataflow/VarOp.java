package bcpi.dataflow;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.SequenceNumber;

import java.util.Objects;

/**
 * A (variable, program point) pair for Partitoned Lattice per Variable (PLV) problems.
 */
public final class VarOp {
	private final Varnode var;
	private final PcodeOp op;

	public VarOp(Varnode var, PcodeOp op) {
		this.var = Objects.requireNonNull(var);
		this.op = op;
	}

	/**
	 * @return The variable.
	 */
	public Varnode getVar() {
		return this.var;
	}

	/**
	 * @return The pcode operation, if any.
	 */
	public PcodeOp getOp() {
		return this.op;
	}

	/**
	 * @return The program point, if any.
	 */
	public SequenceNumber getSeqnum() {
		if (this.op == null) {
			return null;
		} else {
			return this.op.getSeqnum();
		}
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (obj instanceof VarOp other) {
			return Objects.equals(this.var, other.var)
				&& Objects.equals(this.getSeqnum(), other.getSeqnum());
		} else {
			return false;
		}
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.var, this.getSeqnum());
	}

	@Override
	public String toString() {
		return String.format("%s @ %s", this.var, this.getSeqnum());
	}
}
