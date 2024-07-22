package bcpi;

import bcpi.util.Log;
import bcpi.util.StreamUtils;

import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

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
		Log.info("Adding coverage from %,d instructions", rows.size());

		rows.stream()
			.forEach(row -> {
				long count = row.getCount(BcpiConfig.INSTRUCTION_COUNTER);
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
	 * @return The function calls in this function.
	 */
	public List<Reference> getCallsFrom(Function func) {
		var refs = func.getProgram().getReferenceManager();
		var addrs = func.getBody().getAddresses(true);
		return StreamUtils.stream(addrs)
			.map(refs::getReferencesFrom)
			.filter(Objects::nonNull)
			.flatMap(StreamUtils::stream)
			.filter(ref -> ref.getReferenceType().isCall())
			.collect(Collectors.toList());
	}

	/**
	 * @return The functions called by this function.
	 */
	public Set<Function> getCalledFunctions(Function func) {
		return getCallsFrom(func)
			.stream()
			.map(Reference::getToAddress)
			.map(ctx::getFunctionAt)
			.filter(Objects::nonNull)
			.collect(Collectors.toSet());
	}

	/**
	 * @return The calls to this function.
	 */
	public Collection<Reference> getCallsTo(Function func) {
		var refMan = func.getProgram().getReferenceManager();
		var refs = refMan.getReferencesTo(func.getEntryPoint());
		return StreamUtils.stream(refs)
			.filter(ref -> ref.getReferenceType().isCall())
			.collect(Collectors.toList());
	}

	/**
	 * @return The functions that call this function.
	 */
	public Set<Function> getCallingFunctions(Function func) {
		return getCallsTo(func)
			.stream()
			.map(Reference::getFromAddress)
			.map(ctx::getFunctionContaining)
			.filter(Objects::nonNull)
			.collect(Collectors.toSet());
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
				for (Function callee : getCalledFunctions(caller)) {
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
