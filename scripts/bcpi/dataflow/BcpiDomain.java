package bcpi.dataflow;

import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.Collection;
import java.util.Objects;

/**
 * The BCPI abstract domain.
 */
public class BcpiDomain implements Domain<BcpiDomain> {
	private final VarDomain<BcpiVarDomain> vars;

	private BcpiDomain(VarDomain<BcpiVarDomain> vars) {
		this.vars = vars;
	}

	/**
	 * @return The bottom lattice element.
	 */
	public static BcpiDomain bottom() {
		return new BcpiDomain(VarDomain.bottom(BcpiVarDomain.bottom()));
	}

	/**
	 * @return Whether this is the bottom lattice element.
	 */
	public boolean isBottom() {
		return this.vars.isBottom();
	}

	/**
	 * @return The abstract state for a called function.
	 */
	public static BcpiDomain forCall(PcodeOp op, HighFunction func, DataFlow<BcpiDomain> caller) {
		var callee = bottom();
		var locals = func.getLocalSymbolMap();
		var args = op.getInputs();

		for (int i = 0; i < locals.getNumParams() && i + 1 < args.length; ++i) {
			var param = locals.getParam(i);
			if (param == null) {
				continue;
			}
			for (var vn : param.getInstances()) {
				// Copy abstract values from the call arguments to the formal parameters
				var state = caller.fixpoint(vn);
				var arg = state.vars.get(args[i + 1]);
				callee.vars.put(vn, arg);
			}
		}

		return callee;
	}

	/**
	 * @return The abstract value for the given pointer.
	 */
	public PtrDomain getPtrFacts(Varnode vn) {
		return this.vars.get(vn).getPtrFacts();
	}

	/**
	 * @return The abstract value for the given integer.
	 */
	public IntDomain getIntFacts(Varnode vn) {
		return this.vars.get(vn).getIntFacts();
	}

	@Override
	public BcpiDomain copy() {
		return new BcpiDomain(this.vars.copy());
	}

	@Override
	public boolean joinInPlace(BcpiDomain other) {
		return this.vars.joinInPlace(other.vars);
	}

	@Override
	public Collection<PcodeOp> getInputs(PcodeOp op) {
		return this.vars.getInputs(op);
	}

	@Override
	public boolean supports(PcodeOp op) {
		return this.vars.supports(op);
	}

	@Override
	public BcpiDomain visit(PcodeOp op) {
		return new BcpiDomain(this.vars.visit(op));
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof BcpiDomain)) {
			return false;
		}

		var other = (BcpiDomain) obj;
		return this.vars.equals(other.vars);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.vars);
	}

	@Override
	public String toString() {
		return this.vars.toString();
	}
}
