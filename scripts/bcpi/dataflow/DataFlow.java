package bcpi.dataflow;

import bcpi.util.WorkList;

import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.SequenceNumber;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * The generic data flow analysis algorithm.
 */
public final class DataFlow<T extends Domain<T>> {
	private final T domain;
	private final ConcurrentMap<VarOp, T> cache;

	/**
	 * Create a new data flow context.
	 *
	 * @param domain
	 *            The initial value of the analysis domain.
	 */
	public DataFlow(T domain) {
		this.domain = domain;
		this.cache = new ConcurrentHashMap<>();
	}

	/**
	 * @return The solution to the data flow equations at the given program point.
	 */
	public T fixpoint(VarOp vop) {
		// We use a work-list algorithm to iterate until fixpoint
		var workList = new WorkList<VarOp>();

		// Cache each operation's inputs/outputs
		var inputs = new HashMap<VarOp, List<VarOp>>();
		var outputs = new HashMap<VarOp, List<VarOp>>();

		// Keep a separate local cache for thread safety
		var cache = new HashMap<VarOp, T>();

		// Add the (transitive) inputs to the work list
		var inputList = new WorkList<VarOp>();
		inputList.addLast(vop);
		while (!inputList.isEmpty()) {
			var work = inputList.removeFirst();

			var state = this.cache.get(work);
			if (state != null) {
				// Data flow is already solved, use the cached state
				cache.put(work, state);
				continue;
			}

			state = this.domain.initial(work);
			cache.put(work, state);

			if (!state.supports(work)) {
				continue;
			}

			if (!workList.addFirst(work)) {
				throw new RuntimeException("COW");
			}

			var workInputs = state.getInputs(work);
			inputs.put(work, workInputs);

			for (var input : workInputs) {
				outputs.computeIfAbsent(input, k -> new ArrayList<>())
					.add(work);
				if (!workList.contains(input)) {
					inputList.addLast(input);
				}
			}
		}

		var inputStates = new ArrayList<T>();

		// Process the work list until it's empty
		while (!workList.isEmpty()) {
			var work = workList.removeFirst();

			var state = cache.get(work);

			// Get the current value of each input
			inputStates.clear();
			var workInputs = inputs.getOrDefault(work, List.of());
			for (var input : workInputs) {
				inputStates.add(cache.get(input));
			}

			// State is dirty, update it with new inputs
			if (state.visit(work, inputStates)) {
				// State changed, dirty its outputs
				var workOutputs = outputs.getOrDefault(work, List.of());
				for (var output : workOutputs) {
					workList.addLast(output);
				}
			}
		}

		// Save solutions for future calls
		this.cache.putAll(cache);

		return cache.get(vop);
	}

	/**
	 * @return The solution to the data flow equations at a varnode's definition.
	 */
	public T fixpoint(Varnode vn) {
		return fixpoint(new VarOp(vn, vn.getDef()));
	}

	/**
	 * Create a nested data flow analysis for a function call.
	 */
	public DataFlow<T> forCall(PcodeOp op, HighFunction func) {
		var callee = new DataFlow<>(this.domain.copy());
		var locals = func.getLocalSymbolMap();
		var args = op.getInputs();

		for (int i = 0; i < locals.getNumParams() && i + 1 < args.length; ++i) {
			var param = locals.getParam(i);
			if (param == null) {
				continue;
			}

			// args[0] is the return address
			var argVar = args[i + 1];
			var argState = fixpoint(argVar);

			for (var paramVar : param.getInstances()) {
				// Copy abstract values from the call arguments to the formal parameters
				var paramVop = new VarOp(paramVar, paramVar.getDef());
				callee.cache.put(paramVop, argState);
			}
		}

		return callee;
	}
}
