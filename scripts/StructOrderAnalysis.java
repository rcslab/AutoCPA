import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangReturnType;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangTypeToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.parallel.DecompileConfigurer;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.extension.datatype.finder.DecompilerVariable;
import ghidra.app.extension.datatype.finder.DecompilerReference;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeReference;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.BufferedReader;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Analyzes cache misses to suggest reorderings of struct fields.
 */
public class StructOrderAnalysis extends GhidraScript {
	private final Map<Address, Integer> data = new HashMap<>();
	private final Map<Address, Set<DataTypeComponent>> refs = new ConcurrentHashMap<>();
	private final AtomicInteger decompileCount = new AtomicInteger();

	@Override
	public void run() throws Exception {
		Path csvIn = Paths.get(getScriptArgs()[0]);
		Path csvOut = Paths.get(getScriptArgs()[1]);

		// Read address_info.csv to find relevant addresses
		try (BufferedReader reader = Files.newBufferedReader(csvIn)) {
			String line = null;
			while ((line = reader.readLine()) != null) {
				String values[] = line.split(",");
				int count = Integer.parseInt(values[0]);
				Address[] addresses = currentProgram.parseAddress(values[1]);
				for (Address address : addresses) {
					this.data.put(address, count);
				}
			}
		}

		// Get the decompilation of each function containing an address
		// for which we have data.  This is much faster than calling
		// DataTypeReferenceFinder once per field.
		Listing listing = this.currentProgram.getListing();
		Set<Function> functions = new HashSet<>();
		for (Address address : this.data.keySet()) {
			Function func = listing.getFunctionContaining(address);
			if (func != null) {
				functions.add(func);
			}
		}

		QCallback callback = new QCallback();
		try {
			ParallelDecompiler.decompileFunctions(callback, functions, this.monitor);
		} catch (Exception e) {
			Msg.error(this, "Operation failed", e);
		} finally {
			callback.dispose();
		}

		Msg.info(this, "Decompiled " + this.decompileCount.intValue() + " functions");

		int refCount = 0;
		try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(csvOut))) {
			for (Map.Entry<Address, Set<DataTypeComponent>> entry : this.refs.entrySet()) {
				Address address  = entry.getKey();
				Set<DataTypeComponent> fields = entry.getValue();
				refCount += fields.size();
				for (DataTypeComponent field : fields) {
					DataType parent = field.getParent();
					writer.printf("%s,\"%s\",%d,\"%s\",\"%s\"\n",
						address,
						parent.getDataTypePath().getPath(),
						field.getOffset(),
						parent.getCategoryPath().getPath(),
						parent.getCategoryPath().getName());
				}
			}
		}
		Msg.info(this, "Found " + refCount + " field references");
	}

	/**
	 * Based on Ghidra's DecompilerDataTypeReferenceFinder.
	 */
	private class QCallback extends DecompilerCallback<Void> {
		QCallback() {
			super(currentProgram, new DecompilerConfigurer());
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

		ClangTokenGroup tokens = results.getCCodeMarkup();
		if (tokens == null) {
			Msg.warn(this, "Failed to decompile " + function.getName());
			return;
		}

		for (ClangLine line : DecompilerUtils.toLines(tokens)) {
			processLine(line);
		}
	}

	/**
	 * Process a single line of a decompiled function.
	 */
	private void processLine(ClangLine line) {
		for (ClangToken token : line.getAllTokens()) {
			if (token instanceof ClangFieldToken) {
				processField((ClangFieldToken) token);
			}
		}
	}

	/**
	 * Process a field access.
	 */
	private void processField(ClangFieldToken token) {
		DataTypeComponent field = getField(token);
		if (field == null || ignoreDataType(field.getParent())) {
			return;
		}

		Address address = getAddress(token);
		this.refs.computeIfAbsent(address, a -> ConcurrentHashMap.newKeySet())
			.add(field);
	}

	/**
	 * Finds the field associated with a ClangFieldToken.
	 */
	private DataTypeComponent getField(ClangFieldToken token) {
		DataType baseType = DecompilerReference.getBaseType(token.getDataType());

		if (baseType instanceof Structure) {
			Structure parent = (Structure) baseType;
			int offset = token.getOffset();
			if (offset >= 0 && offset < parent.getLength()) {
				return parent.getComponentAt(offset);
			}
		}

		return null;
	}

	/**
	 * Finds the address of a field access.
	 */
	private Address getAddress(ClangFieldToken token) {
		// Access DecompilerVariable's protected constructor through an
		// anonymous subclass
		return (new DecompilerVariable(token) {}).getAddress();
	}

	/**
	 * Check if a struct should be processed.  We are looking for non-system
	 * DWARF types.
	 */
	private boolean ignoreDataType(DataType type) {
		String name = type.getPathName();

		if (!name.startsWith("/DWARF/")) {
			return true;
		}

		if (name.contains("/std/")
		    || name.contains("/stdlib.h/")
		    || name.contains("/stdio.h/")
		    || name.contains("/_UNCATEGORIZED_/")) {
			return true;
		}

		return false;
	}
}
