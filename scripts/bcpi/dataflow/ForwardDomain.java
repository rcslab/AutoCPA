package bcpi.dataflow;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Base class for forward data flow analysis domains.
 */
public abstract class ForwardDomain<T extends Lattice<T>> implements Domain<T> {
	@Override
	public Collection<PcodeOp> getInputs(PcodeOp op) {
		return Arrays.stream(op.getInputs())
			.map(Varnode::getDef)
			.filter(Objects::nonNull)
			.collect(Collectors.toList());
	}
}
