package bcpi.dataflow;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.Collection;

/**
 * A sparse (per-varnode) abstract domain.
 */
public interface SparseDomain<T extends Lattice<T>, U> extends Lattice<T> {
	/**
	 * @return The initial value for the given varnode.
	 */
	T getDefault(Varnode vn);

	/**
	 * @return Whether the visit() method supports the given operation.
	 */
	boolean supports(PcodeOp op);

	/**
	 * The transfer function.
	 *
	 * @param op
	 *            The current program point.
	 * @param map
	 *            A function that maps varnodes to an abstract domain.
	 * @return The abstract value of the output varnode.
	 */
	T visit(PcodeOp op, VarMap<U> map);
}
