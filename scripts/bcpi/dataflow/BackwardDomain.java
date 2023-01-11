package bcpi.dataflow;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import com.google.common.collect.Lists;

import java.util.Collection;
import java.util.Collections;

/**
 * Base class for backward data flow analysis domains.
 */
public abstract class BackwardDomain<T extends Lattice<T>> implements Domain<T> {
	@Override
	public Collection<PcodeOp> getInputs(PcodeOp op) {
		var output = op.getOutput();
		if (output == null) {
			return Collections.emptyList();
		} else {
			return Lists.newArrayList(output.getDescendants());
		}
	}
}
