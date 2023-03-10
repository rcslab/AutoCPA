package bcpi;

import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Whole-program control flow information.
 */
public class BcpiControlFlow {
	private final ConcurrentMap<Function, ControlFlowGraph> cfgs = new ConcurrentHashMap<>();
	private final AnalysisContext ctx;

	public BcpiControlFlow(AnalysisContext ctx) {
		this.ctx = ctx;
	}

	/**
	 * Add coverage information to the CFGs
	 */
	public void addCoverage(BcpiData data) {
		Collection<BcpiDataRow> rows = data.getRows();
		Msg.info(this, String.format("Adding coverage from %,d instructions", rows.size()));

		rows.stream()
			.forEach(row -> {
				int count = row.getCount(BcpiConfig.INSTRUCTION_COUNTER);
				ControlFlowGraph cfg = getCfg(row.function);
				synchronized (cfg) {
					cfg.addCoverage(row.address, count);
				}
			});
	}

	/**
	 * @return The cached CFG for a function.
	 */
	public ControlFlowGraph getCfg(Function function) {
		return this.cfgs.computeIfAbsent(function, f -> new ControlFlowGraph(f));
	}

	/**
	 * @return The set of functions reachable from the given entry points, up to a certain depth.
	 */
	public Set<Function> getCalledFunctions(Collection<Function> funcs, int maxDepth) {
		var linker = this.ctx.getLinker();
		Set<Function> result = new HashSet<>(funcs);

		// Add called functions breadth-first
		Set<Function> oldFuncs = result;
		for (int depth = 0; depth < maxDepth; ++depth) {
			Set<Function> newFuncs = new HashSet<>();
			for (Function caller : oldFuncs) {
				for (Function callee : caller.getCalledFunctions(TaskMonitor.DUMMY)) {
					Optional.of(callee)
						.flatMap(linker::resolve)
						.filter(f -> !result.contains(f))
						.ifPresent(newFuncs::add);
				}
			}

			result.addAll(newFuncs);
			oldFuncs = newFuncs;
		}

		return result;
	}
}
