package bcpi.dataflow;

import ghidra.program.model.pcode.PcodeOp;

import java.util.Collection;

/**
 * An abstract domain for data flow analysis.
 */
public interface Domain<T extends Lattice<T>> extends Lattice<T> {
	/**
	 * @return Whether the visit() method supports the given operation.
	 */
	boolean supports(PcodeOp op);

	/**
	 * @return The set of program points that op depends on.
	 */
	Collection<PcodeOp> getInputs(PcodeOp op);

	/**
	 * The transfer function.
	 *
	 * @return The abstract value at the program point op.
	 */
	T visit(PcodeOp op);
}
