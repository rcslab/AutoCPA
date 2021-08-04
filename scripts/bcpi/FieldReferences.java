package bcpi;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompileConfigurer;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import generic.concurrent.QCallback;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Maps code addresses to the struct field(s) they reference.
 */
public class FieldReferences {
	private final Map<Address, Set<FieldReference>> refs = new ConcurrentHashMap<>();
	private final AtomicInteger decompileCount = new AtomicInteger();

	/**
	 * Collect the struct field references in the specified functions.
	 */
	public void collect(Program program, Set<Function> functions, TaskMonitor monitor) throws Exception {
		int prevCount = decompileCount.intValue();
		int prevSize = this.size();

		Callback callback = new Callback(program);
		try {
			decompileFunctions(callback, program, functions, monitor);
		} finally {
			callback.dispose();
		}

		int newCount = this.decompileCount.intValue() - prevCount;
		if (newCount > 0) {
			Msg.info(this, program.getName() + ": decompiled " + newCount + " functions");
		}

		int newSize = this.size() - prevSize;
		if (newSize > 0) {
			Msg.info(this, program.getName() + ": found " + newSize + " field references");
		}
	}

	private int size() {
		int size = 0;
		for (Map.Entry<Address, Set<FieldReference>> entry : this.refs.entrySet()) {
			size += entry.getValue().size();
		}
		return size;
	}

	/**
	 * Facade over ParallelDecompiler::decompileFunctions() that handles the API change between
	 * Ghidra 9.1 and 9.2.
	 */
	<R> void decompileFunctions(QCallback<Function, R> callback, Program program, Collection<Function> functions, TaskMonitor monitor) throws Exception {
		MethodHandles.Lookup lookup = MethodHandles.lookup();
		MethodHandle method92 = null;
		MethodHandle method91 = null;
		try {
			MethodType type92 = MethodType.methodType(List.class, QCallback.class, Collection.class, TaskMonitor.class);
			method92 = lookup.findStatic(ParallelDecompiler.class, "decompileFunctions", type92);
		} catch (ReflectiveOperationException e) {
			MethodType type91 = MethodType.methodType(List.class, QCallback.class, Program.class, Collection.class, TaskMonitor.class);
			method91 = lookup.findStatic(ParallelDecompiler.class, "decompileFunctions", type91);
		}

		try {
			if (method92 != null) {
				method92.invoke(callback, functions, monitor);
			} else {
				method91.invoke(callback, program, functions, monitor);
			}
		} catch (Exception e) {
			throw e;
		} catch (Throwable e) {
			throw new Exception(e);
		}
	}

	/**
	 * Get the fields accessed at a particular address.
	 */
	public Set<FieldReference> getFields(Address address) {
		return this.refs.getOrDefault(address, Collections.emptySet());
	}

	/**
	 * Based on Ghidra's DecompilerDataTypeReferenceFinder.
	 */
	private class Callback extends DecompilerCallback<Void> {
		Callback(Program program) {
			super(program, new DecompilerConfigurer());
		}

		@Override
		public Void process(DecompileResults results, TaskMonitor monitor) {
			processDecompilation(results);
			return null;
		}
	}

	private static class DecompilerConfigurer implements DecompileConfigurer {
		@Override
		public void configure(DecompInterface decompiler) {
			decompiler.toggleCCode(true);
			decompiler.toggleSyntaxTree(true);
			decompiler.setSimplificationStyle("decompile");

			DecompileOptions xmlOptions = new DecompileOptions();
			xmlOptions.setDefaultTimeout(60);
			xmlOptions.setMaxPayloadMBytes​(128);
			decompiler.setOptions(xmlOptions);
		}
	}

	/**
	 * Process a single decompiled function.
	 */
	void processDecompilation(DecompileResults results) {
		int count = this.decompileCount.incrementAndGet();
		if (count % 1000 == 0) {
			Msg.info(this, "Decompiled " + count + " functions");
		}

		Function function = results.getFunction();
		if (function.isThunk()) {
			return;
		}

		HighFunction highFunc = results.getHighFunction();
		if (highFunc == null) {
			Msg.warn(this, results.getErrorMessage());
			return;
		}

		PcodeDataFlow dataFlow = new PcodeDataFlow();
		Iterable<PcodeOpAST> ops = () -> highFunc.getPcodeOps();
		for (PcodeOp op : ops) {
			processPcodeOp(dataFlow, op);
		}
	}

	/**
	 * Process a single pcode instruction.
	 */
	private void processPcodeOp(PcodeDataFlow dataFlow, PcodeOp op) {
		if (op.getOpcode() != PcodeOp.LOAD && op.getOpcode() != PcodeOp.STORE) {
			return;
		}

		Varnode[] inputs = op.getInputs();
		// input1: Varnode containing pointer offset (to data|of destination)
		Varnode ptr = inputs[1];

		Facts facts = dataFlow.getFacts(ptr);
		Field field = facts.getField();
		if (field == null) {
			return;
		}

		Address address = op.getSeqnum().getTarget();
		this.refs.computeIfAbsent(address, a -> ConcurrentHashMap.newKeySet())
			.add(new FieldReference(field, facts.isArray()));
	}
}
