package bcpi.dataflow;

import java.util.List;

/**
 * An abstract domain for data flow analysis.
 */
public interface Domain<T extends Lattice<T>> extends Lattice<T> {
	/**
	 * @return The initial value for the given variable.
	 */
	T initial(VarOp vop);

	/**
	 * @return Whether the visit() method supports the given operation.
	 */
	boolean supports(VarOp vop);

	/**
	 * @return The list of program points that vop depends on.
	 */
	List<VarOp> getInputs(VarOp vop);

	/**
	 * The transfer function.
	 *
	 * @param vop
	 *            The current variable and program point.
	 * @param inputs
	 *            The current abstract values for the inputs.
	 * @return Whether this value changed.
	 */
	boolean visit(VarOp vop, List<T> inputs);
}
