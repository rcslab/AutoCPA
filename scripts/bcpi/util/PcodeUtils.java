package bcpi.util;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.function.Predicate;

/**
 * P-code utilities.
 */
public final class PcodeUtils {
	private PcodeUtils() {
	}

	/**
	 * @return Whether a p-code operation accesses memory.
	 */
	public static boolean isMemoryAccess(PcodeOp op) {
		switch (op.getOpcode()) {
		case PcodeOp.LOAD:
		case PcodeOp.STORE:
			return true;
		default:
			return false;
		}
	}

	/**
	 * @return Whether an instruction accesses memory.
	 */
	public static boolean isMemoryAccess(Instruction inst) {
		return StreamUtils.stream(inst.getPcode())
			.anyMatch(PcodeUtils::isMemoryAccess);
	}

	/**
	 * @return Whether we consider this p-code op a feasible cause of a cache miss.
	 */
	public static boolean isFeasibleCacheMiss(PcodeOp op) {
		if (!isMemoryAccess(op)) {
			return false;
		}

		// Get the pointer varnode being accessed
		var ptr = op.getInput(1);

		// Stack accesses are unlikely to cause cache misses, more
		// likely to be due to skid
		if (ptr.getSpace() == AddressSpace.TYPE_STACK) {
			return false;
		}

		return true;
	}

	/**
	 * @return Whether we consider this instruction a feasible cause of a cache miss.
	 */
	public static boolean isFeasibleCacheMiss(Instruction inst) {
		return StreamUtils.stream(inst.getPcode())
			.anyMatch(PcodeUtils::isFeasibleCacheMiss);
	}

	/**
	 * Attempt to undo PMC skid by filtering out infeasible instructions.
	 */
	public static Instruction tryUndoSkid(Instruction inst, Predicate<Instruction> feasible) {
		// Fast path: avoid looking up the basic block at all
		if (feasible.test(inst)) {
			return inst;
		}

		var program = inst.getProgram();
		var bbModel = new BasicBlockModel(program);

		CodeBlock block = null;
		try {
			block = bbModel.getFirstCodeBlockContaining(inst.getAddress(), TaskMonitor.DUMMY);
		} catch (CancelledException e) {
		}
		if (block == null) {
			return inst;
		}

		// Walk backwards through instructions in the same basic block
		for (var prev = inst.getPrevious(); block.contains(prev.getAddress()); prev = prev.getPrevious()) {
			if (feasible.test(prev)) {
				return prev;
			}
		}

		return inst;
	}
}
