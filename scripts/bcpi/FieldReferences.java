package bcpi;

import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.parallel.DecompileConfigurer;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.extension.datatype.finder.DecompilerVariable;
import ghidra.app.extension.datatype.finder.DecompilerReference;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
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
	private final Map<Address, Set<DataTypeComponent>> refs = new ConcurrentHashMap<>();
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
		for (Map.Entry<Address, Set<DataTypeComponent>> entry : this.refs.entrySet()) {
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
	public Set<DataTypeComponent> getFields(Address address) {
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
