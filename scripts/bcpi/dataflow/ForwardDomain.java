package bcpi.dataflow;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Base class for forward data flow analysis domains.
 */
public abstract class ForwardDomain<T extends Lattice<T>> implements Domain<T> {
	@Override
	public List<VarOp> getInputs(VarOp vop) {
		var op = vop.getOp();
		if (op == null) {
			return List.of();
		}

		return Arrays.stream(op.getInputs())
			.map(vn -> new VarOp(vn, vn.getDef()))
			.collect(Collectors.toList());
	}
}
