package bcpi;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompileConfigurer;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import generic.concurrent.GThreadPool;

import com.google.common.base.Throwables;
import com.google.common.collect.Multimap;
import com.google.common.collect.Multimaps;

import java.util.Collection;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Wrapper around Ghidra's pcode decompiler.
 */
public class BcpiDecompiler {
	private final ConcurrentMap<Function, HighFunction> pcode = new ConcurrentHashMap<>();
	private final Set<Function> warned = ConcurrentHashMap.newKeySet();

	public void decompile(Collection<Function> funcs) {
		// Bump up the thread count
		int threads = 2 * Runtime.getRuntime().availableProcessors();
		GThreadPool
			.getSharedThreadPool("Parallel Decompiler")
			.setMaxThreadCount(threads);

		// Group functions by program since Ghidra requires it
		Multimap<Program, Function> index = Multimaps.index(funcs, Function::getProgram);
		for (Program program : index.keySet()) {
			decompile(program, index.get(program));
		}
	}

	private void decompile(Program program, Collection<Function> functions) {
		Msg.info(this, String.format("%s: decompiling %,d functions", program.getName(), functions.size()));

		DecompileConfigurer config = new DecompileConfigurer() {
			@Override
			public void configure(DecompInterface decompiler) {
				decompiler.toggleCCode(true);
				decompiler.toggleSyntaxTree(true);
				decompiler.setSimplificationStyle("decompile");

				DecompileOptions xmlOptions = new DecompileOptions();
				xmlOptions.setDefaultTimeout(60);
				xmlOptions.setMaxPayloadMBytes(128);
				decompiler.setOptions(xmlOptions);
			}
		};

		DecompilerCallback<Void> callback = new DecompilerCallback<Void>(program, config) {
			@Override
			public Void process(DecompileResults results, TaskMonitor monitor) {
				processDecompilation(results);
				return null;
			}
		};

		try {
			ParallelDecompiler.decompileFunctions(callback, functions, TaskMonitor.DUMMY);
		} catch (Exception e) {
			throw Throwables.propagate(e);
		} finally {
			callback.dispose();
		}
	}

	/**
	 * Process a single decompiled function.
	 */
	private void processDecompilation(DecompileResults results) {
		Function function = results.getFunction();
		HighFunction highFunc = results.getHighFunction();
		if (highFunc == null) {
			Msg.warn(this, function.getName() + ": " + results.getErrorMessage().strip());
			return;
		}

		this.pcode.put(function, highFunc);
	}

	/**
	 * @return The decompiled pcode for the given function.
	 */
	public HighFunction getPcode(Function function) {
		HighFunction result = this.pcode.get(function);
		if (result == null) {
			if (this.warned.add(function)) {
				Msg.warn(this, "Couldn't find pcode for " + function);
			}
		}
		return result;
	}
}
