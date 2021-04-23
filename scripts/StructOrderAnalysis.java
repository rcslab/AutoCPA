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
import ghidra.app.script.GhidraScript;
import ghidra.graph.DefaultGEdge;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.graph.GraphAlgorithms;
import ghidra.graph.jung.JungDirectedGraph;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import generic.concurrent.QCallback;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.HashMultiset;
import com.google.common.collect.Multiset;
import com.google.common.collect.Multisets;
import com.google.common.collect.SetMultimap;

import java.io.BufferedReader;
import java.io.IOException;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Analyzes cache misses to suggest reorderings of struct fields.
 */
public class StructOrderAnalysis extends GhidraScript {
	@Override
	public void run() throws Exception {
		// Read address_info.csv to find relevant addresses
		String[] args = getScriptArgs();
		Path csv = Paths.get(args[0]);
		BcpiData data = BcpiData.parse(csv, this.currentProgram);

		// Get the decompilation of each function containing an address
		// for which we have data.  This is much faster than calling
		// DataTypeReferenceFinder once per field.
		Set<Function> functions = data.getRelevantFunctions();
		FieldReferences refs = FieldReferences.collect(this.currentProgram, functions, this.monitor);

		// Use our collected data to infer field access patterns
		AccessPatterns patterns = AccessPatterns.collect(this.currentProgram, data, refs, this.monitor);

		if (args.length > 1) {
			printDetails(patterns, args[1]);
		} else {
			printSummary(patterns);
		}
	}

	private static class SummaryRow {
		final Structure struct;
		final int nSamples;
		final int nPatterns;
		final int improvement;

		SummaryRow(Structure struct, int nSamples, int nPatterns, int improvement) {
			this.struct = struct;
			this.nSamples = nSamples;
			this.nPatterns = nPatterns;
			this.improvement = improvement;
		}
	}

	private void printSummary(AccessPatterns patterns) {
		List<SummaryRow> rows = new ArrayList<>();
		for (Structure struct : patterns.getStructures()) {
			int nSamples = 0;
			int nPatterns = 0;
			for (AccessPattern pattern : patterns.getPatterns(struct)) {
				nSamples += patterns.getCount(struct, pattern);
				nPatterns += 1;
			}

			int before = patterns.score(struct, struct);
			int after = patterns.score(struct, patterns.optimize(struct));
			rows.add(new SummaryRow(struct, nSamples, nPatterns, before - after));
		}

		Collections.sort(rows, Comparator
			.<SummaryRow>comparingInt(r -> r.improvement)
			.reversed());

		Table table = new Table();
		table.addColumn(); // Struct name
		table.addColumn(); // Samples
		table.addColumn(); // Patterns
		table.addColumn(); // Improvement

		for (SummaryRow row : rows) {
			int n = table.addRow();
			table.get(n, 0)
				.append(row.struct.getName());
			table.get(n, 1)
				.append(row.nSamples)
				.append(" samples");
			table.get(n, 2)
				.append(row.nPatterns)
				.append(" patterns");
			table.get(n, 3)
				.append("improvement: ")
				.append(row.improvement);
		}

		System.out.print("Found data for these structs:\n\n");
		System.out.print(table);
	}

	private void printDetails(AccessPatterns patterns, String filterRegex) {
		for (Structure struct : patterns.getStructures()) {
			if (!struct.getName().matches(filterRegex)) {
				continue;
			}

			printOriginal(patterns, struct);
			int before = patterns.score(struct, struct);

			Structure optimized = patterns.optimize(struct);
			printOptimized(optimized);
			int after = patterns.score(struct, optimized);

			System.out.format("Improvement: %d (before: %d, after: %d)\n", before - after, before, after);

			System.out.print("\n---\n");
		}
	}

	private void printOriginal(AccessPatterns patterns, Structure struct) {
		System.out.print("\nAccess patterns:\n\n");

		Set<AccessPattern> structPatterns = patterns.getPatterns(struct);
		for (AccessPattern pattern : structPatterns) {
			int count = patterns.getCount(struct, pattern);
			System.out.format("%s (%d times)\n", pattern, count);
			for (Function func : patterns.getFunctions(pattern)) {
				System.out.format("\t- %s()\n", func.getName());
			}
			System.out.println();
		}

		Table table = new Table();
		table.addColumn(); // Field type
		table.addColumn(); // Field name

		table.addRow();
		table.get(0, 0)
			.append("struct ")
			.append(struct.getName())
			.append(" {");

		Map<DataTypeComponent, Integer> rows = new HashMap<>();
		int padding = 0;
		for (DataTypeComponent field : struct.getComponents()) {
			if (field.getDataType().equals(DefaultDataType.dataType)) {
				padding += field.getLength();
			} else {
				addPadding(table, padding);
				padding = 0;

				int row = addField(table, field);
				rows.put(field, row);
			}
		}
		addPadding(table, padding);

		int commentCol = table.addColumn();
		table.get(0, commentCol).append("//");
		for (int row : rows.values()) {
			table.get(row, commentCol).append("//");
		}

		int total = patterns.getCount(struct);
		int count = 0;
		for (AccessPattern pattern : structPatterns) {
			int col = table.addColumn();

			int percent = 100 * patterns.getCount(struct, pattern) / total;
			table.get(0, col)
				.append(percent)
				.append("%");

			for (DataTypeComponent field : pattern.getFields()) {
				table.get(rows.get(field), col).append("*");
			}

			// Don't make the table too wide
			if (++count >= 4) {
				break;
			}
		}
		if (structPatterns.size() > count) {
			int col = table.addColumn();
			table.get(0, col).append("...");
		}

		System.out.print("Original layout:\n\n");
		System.out.print(table);
		System.out.print("};\n\n");
	}

	private void printOptimized(Structure struct) {
		System.out.print("Suggested layout:\n\n");
		System.out.format("struct %s {\n", struct.getName());

		Table table = new Table();
		table.addColumn(); // Field type
		table.addColumn(); // Field name

		int padding = 0;
		for (DataTypeComponent field : struct.getComponents()) {
			if (field.getDataType().equals(DefaultDataType.dataType)) {
				padding += field.getLength();
			} else {
				addPadding(table, padding);
				padding = 0;

				addField(table, field);
			}
		}
		addPadding(table, padding);

		System.out.print(table);
		System.out.print("};\n\n");
	}

	private int addField(Table table, DataTypeComponent field) {
		int row = table.addRow();
		table.get(row, 0)
			.append("        ")
			.append(field.getDataType().getName());
		table.get(row, 1)
			.append(field.getFieldName())
			.append(";");
		return row;
	}

	private void addPadding(Table table, int padding) {
		if (padding != 0) {
			int row = table.addRow();
			table.get(row, 0)
				.append("        // char");
			table.get(row, 1)
				.append("padding[")
				.append(padding)
				.append("];");
		}
	}
}

/**
 * A properly aligned table.
 */
class Table {
	private final List<List<StringBuilder>> rows = new ArrayList<>();
	private int nCols = 0;

	/**
	 * @return The number of rows.
	 */
	int nRows() {
		return this.rows.size();
	}

	/**
	 * @return The number of columns.
	 */
	int nColumns() {
		return nCols;
	}

	/**
	 * @return The index of the new row.
	 */
	int addRow() {
		List<StringBuilder> row = new ArrayList<>();
		for (int i = 0; i < this.nCols; ++i) {
			row.add(new StringBuilder());
		}
		this.rows.add(row);
		return this.rows.size() - 1;
	}

	/**
	 * Add a new column.
	 */
	int addColumn() {
		for (List<StringBuilder> row : this.rows) {
			row.add(new StringBuilder());
		}
		return this.nCols++;
	}

	/**
	 * @return The StringBuilder in the given cell.
	 */
	StringBuilder get(int row, int col) {
		return this.rows.get(row).get(col);
	}

	@Override
	public String toString() {
		List<Integer> widths = new ArrayList<>();
		for (int i = 0; i < this.nCols; ++i) {
			int width = 0;
			for (List<StringBuilder> row : this.rows) {
				int curWidth = row.get(i).length();
				if (width < curWidth) {
					width = curWidth;
				}
			}
			widths.add(width + 1);
		}

		StringBuilder result = new StringBuilder();
		for (List<StringBuilder> row : this.rows) {
			for (int i = 0; i < this.nCols; ++i) {
				StringBuilder cell = row.get(i);
				result.append(cell);

				int width = widths.get(i);
				for (int j = cell.length(); j < width; ++j) {
					result.append(' ');
				}
			}
			result.append('\n');
		}

		return result.toString();
	}
}

/**
 * Holds the data collected by BCPI.
 */
class BcpiData {
	private final Multiset<Address> data;
	private final Program program;

	private BcpiData(Multiset<Address> data, Program program) {
		this.data = data;
		this.program = program;
	}

	/**
	 * Parse a CSV file generated by bcpiutil.
	 */
	static BcpiData parse(Path csv, Program program) throws IOException {
		Multiset<Address> data = HashMultiset.create();

		try (BufferedReader reader = Files.newBufferedReader(csv)) {
			String line = null;
			while ((line = reader.readLine()) != null) {
				String values[] = line.split(",");
				int count = Integer.parseInt(values[0]);
				Address[] addresses = program.parseAddress(values[1]);
				for (Address address : addresses) {
					data.add(address, count);
				}
			}
		}

		return new BcpiData(data, program);
	}

	/**
	 * @return All the functions that contain an address for which we have data.
	 */
	Set<Function> getRelevantFunctions() {
		Set<Function> functions = new HashSet<>();

		Listing listing = this.program.getListing();
		for (Address address : this.getAddresses()) {
			Function func = listing.getFunctionContaining(address);
			if (func != null) {
				functions.add(func);
			}
		}

		return functions;
	}

	/**
	 * @return All addresses for which we have data.
	 */
	Set<Address> getAddresses() {
		return this.data.elementSet();
	}

	/**
	 * @return The number of events collected for the given address.
	 */
	int getCount(Address address) {
		return this.data.count(address);
	}
}

/**
 * Maps code addresses to the struct field(s) they reference.
 */
class FieldReferences {
	private final Map<Address, Set<DataTypeComponent>> refs = new ConcurrentHashMap<>();
	private final AtomicInteger decompileCount = new AtomicInteger();
	private final Program program;
	private final Set<Function> functions;

	private FieldReferences(Program program, Set<Function> functions) {
		this.program = program;
		this.functions = functions;
	}

	/**
	 * Collect the struct field references in the specified functions.
	 */
	static FieldReferences collect(Program program, Set<Function> functions, TaskMonitor monitor) throws Exception {
		FieldReferences refs = new FieldReferences(program, functions);
		refs.collect(monitor);
		return refs;
	}

	private void collect(TaskMonitor monitor) throws Exception {
		Callback callback = new Callback();
		try {
			decompileFunctions(callback, this.program, this.functions, monitor);
		} finally {
			callback.dispose();
		}

		Msg.info(this, "Decompiled " + this.decompileCount.intValue() + " functions");

		int refCount = 0;
		for (Map.Entry<Address, Set<DataTypeComponent>> entry : this.refs.entrySet()) {
			refCount += entry.getValue().size();
		}
		Msg.info(this, "Found " + refCount + " field references");
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
	Set<DataTypeComponent> getFields(Address address) {
		return this.refs.getOrDefault(address, Collections.emptySet());
	}

	/**
	 * Based on Ghidra's DecompilerDataTypeReferenceFinder.
	 */
	private class Callback extends DecompilerCallback<Void> {
		Callback() {
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

/**
 * A set of fields accessed in a block.
 */
class AccessPattern {
	private final Set<DataTypeComponent> fields;

	AccessPattern(Set<DataTypeComponent> fields) {
		this.fields = fields;
	}

	Set<DataTypeComponent> getFields() {
		return this.fields;
	}

	@Override
	public String toString() {
		StringBuilder result = new StringBuilder();

		DataType struct = null;
		for (DataTypeComponent field : this.fields) {
			if (struct == null) {
				struct = field.getParent();
				result.append(struct.getName())
					.append("::{");
			} else {
				result.append(", ");
			}
			result.append(field.getFieldName());
		}

		return result
			.append("}")
			.toString();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof AccessPattern)) {
			return false;
		}

		AccessPattern other = (AccessPattern) obj;
		return this.fields.equals(other.fields);
	}

	@Override
	public int hashCode() {
		return Objects.hash(fields);
	}
}

/**
 * A code block in a control flow graph.
 *
 * Not using ghidra.program.model.block.graph.CodeBlockVertex because it treats
 * all dummy vertices as equal, but we need two different dummy vertices.
 */
class CodeBlockVertex {
	private final CodeBlock block;
	private final String name;
	final Object key;

	CodeBlockVertex(CodeBlock block) {
		this.block = block;
		this.name = block.getName();

		// Same assumption as Ghidra's CodeBlockVertex: every basic block
		// has a unique min address
		this.key = block.getMinAddress();
	}

	CodeBlockVertex(String name) {
		this.block = null;
		this.name = name;
		this.key = name;
	}

	CodeBlock getCodeBlock() {
		return this.block;
	}

	@Override
	public String toString() {
		return this.name;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof CodeBlockVertex)) {
			return false;
		}

		CodeBlockVertex other = (CodeBlockVertex) obj;
		return this.key.equals(other.key);
	}

	@Override
	public int hashCode() {
		return this.key.hashCode();
	}
}

/**
 * An edge in a control flow graph.
 */
class CodeBlockEdge extends DefaultGEdge<CodeBlockVertex> {
	CodeBlockEdge(CodeBlockVertex from, CodeBlockVertex to) {
		super(from, to);
	}
}

/**
 * A control flow graph of a single function.
 */
class ControlFlowGraph {
	private final BasicBlockModel bbModel;
	private final TaskMonitor monitor;
	private final GDirectedGraph<CodeBlockVertex, GEdge<CodeBlockVertex>> domTree;

	ControlFlowGraph(Function function, BasicBlockModel bbModel, TaskMonitor monitor) throws Exception {
		this.bbModel = bbModel;
		this.monitor = monitor;

		AddressSetView body = function.getBody();
		CodeBlockIterator blocks = bbModel.getCodeBlocksContaining(body, monitor);

		// Workaround for https://github.com/NationalSecurityAgency/ghidra/issues/2836
		Map<CodeBlockVertex, CodeBlockVertex> interner = new HashMap<>();

		// Build the control flow graph for that function.  We want all the nodes B such
		// that all paths from A to END contain B, i.e.
		//
		//     {B | B postDom A}
		//
		// findPostDomainance(A) gets us {B | A postDom B} instead, so we have to compute it
		// by hand.  The post-dominance relation is just the dominance relation on the
		// transposed graph, so we orient all the edges backwards, compute the dominance
		// tree, and walk the parents instead of the children.
		JungDirectedGraph<CodeBlockVertex, CodeBlockEdge> graph = new JungDirectedGraph<>();
		while (blocks.hasNext()) {
			CodeBlock block = blocks.next();
			CodeBlockVertex vertex = interner.computeIfAbsent(new CodeBlockVertex(block), v -> v);
			graph.addVertex(vertex);

			CodeBlockReferenceIterator dests = block.getDestinations(monitor);
			while (dests.hasNext()) {
				CodeBlockReference dest = dests.next();
				CodeBlock destBlock = dest.getDestinationBlock();
				if (!body.contains(destBlock)) {
					// Ignore non-local control flow
					continue;
				}

				CodeBlockVertex destVertex = interner.computeIfAbsent(new CodeBlockVertex(destBlock), v -> v);
				graph.addVertex(destVertex);
				graph.addEdge(new CodeBlockEdge(destVertex, vertex));
			}
		}

		// Make sure the graph has a unique source and sink
		CodeBlockVertex source = new CodeBlockVertex("SOURCE");
		for (CodeBlockVertex vertex : GraphAlgorithms.getSources(graph)) {
			graph.addVertex(source);
			graph.addEdge(new CodeBlockEdge(source, vertex));
		}

		// The function entry point is a sink, since the graph is reversed
		CodeBlockVertex sink = new CodeBlockVertex("SINK");
		for (CodeBlock block : bbModel.getCodeBlocksContaining(function.getEntryPoint(), monitor)) {
			CodeBlockVertex vertex = interner.computeIfAbsent(new CodeBlockVertex(block), v -> v);
			graph.addVertex(sink);
			graph.addEdge(new CodeBlockEdge(vertex, sink));
		}

		this.domTree = GraphAlgorithms.findDominanceTree(graph, monitor);
	}

	/**
	 * Get the basic blocks that are guaranteed to be reached from the given address.
	 */
	Set<CodeBlock> definitelyReachedBlocks(Address address) throws Exception {
		if (this.domTree == null) return Collections.emptySet();

		List<CodeBlockVertex> sources = new ArrayList<>();
		for (CodeBlock block : this.bbModel.getCodeBlocksContaining(address, this.monitor)) {
			sources.add(new CodeBlockVertex(block));
		}

		Set<CodeBlock> blocks = new HashSet<>();
		for (CodeBlockVertex vertex : GraphAlgorithms.getAncestors(this.domTree, sources)) {
			CodeBlock block = vertex.getCodeBlock();
			if (block != null) {
				blocks.add(block);
			}
		}
		return blocks;
	}
}

/**
 * Struct field access patterns.
 */
class AccessPatterns {
	// Stores the access patterns for each struct
	private final Map<Structure, Multiset<AccessPattern>> patterns = new HashMap<>();
	private final SetMultimap<AccessPattern, Function> functions = HashMultimap.create();
	private final Map<Function, ControlFlowGraph> cfgs = new HashMap<>();
	private final Listing listing;
	private final BasicBlockModel bbModel;
	private final BcpiData data;
	private final FieldReferences refs;

	private AccessPatterns(Program program, BcpiData data, FieldReferences refs) {
		this.listing = program.getListing();
		this.bbModel = new BasicBlockModel(program);
		this.data = data;
		this.refs = refs;
	}

	/**
	 * Infer access patterns from the collected data.
	 */
	static AccessPatterns collect(Program program, BcpiData data, FieldReferences refs, TaskMonitor monitor) throws Exception {
		AccessPatterns patterns = new AccessPatterns(program, data, refs);
		patterns.collect(monitor);
		return patterns;
	}

	private void collect(TaskMonitor monitor) throws Exception {
		for (Address baseAddress : this.data.getAddresses()) {
			Map<Structure, Set<DataTypeComponent>> pattern = new HashMap<>();
			int count = this.data.getCount(baseAddress);

			Set<CodeBlock> blocks = getCodeBlocksFrom(baseAddress, monitor);
			for (CodeBlock block : blocks) {
				for (Address address : block.getAddresses(true)) {
					// Don't count accesses before the miss
					if (block.contains(baseAddress) && address.compareTo(baseAddress) < 0) {
						continue;
					}

					for (DataTypeComponent field : this.refs.getFields(address)) {
						Structure struct = (Structure) field.getParent();
						pattern.computeIfAbsent(struct, k -> new HashSet<>())
							.add(field);
					}
				}
			}

			if (pattern.isEmpty()) {
				Msg.warn(this, "No structure accesses found for " + count + " samples at address " + baseAddress);
			}

			for (Map.Entry<Structure, Set<DataTypeComponent>> entry : pattern.entrySet()) {
				AccessPattern accessPattern = new AccessPattern(entry.getValue());
				this.patterns.computeIfAbsent(entry.getKey(), k -> HashMultiset.create())
					.add(accessPattern, count);
				this.functions.put(accessPattern, this.listing.getFunctionContaining(baseAddress));
			}
		}
	}

	/**
	 * @return All the code blocks that flow from the given address.
	 */
	private Set<CodeBlock> getCodeBlocksFrom(Address address, TaskMonitor monitor) throws Exception {
		// Get all the basic blocks in the function contining the given address
		Function function = this.listing.getFunctionContaining(address);
		if (function == null) {
			return Collections.emptySet();
		}

		ControlFlowGraph cfg = this.cfgs.get(function);
		if (cfg == null) {
			cfg = new ControlFlowGraph(function, this.bbModel, monitor);
			this.cfgs.put(function, cfg);
		}

		return cfg.definitelyReachedBlocks(address);
	}

	/**
	 * @return All the structures about which we have data.
	 */
	Set<Structure> getStructures() {
		return this.patterns.keySet();
	}

	/**
	 * @return All the access patterns we saw for a structure, from most to least often.
	 */
	Set<AccessPattern> getPatterns(Structure struct) {
		return Multisets.copyHighestCountFirst(this.patterns.get(struct))
			.elementSet();
	}

	/**
	 * @return The total number of accesses to a struct.
	 */
	int getCount(Structure struct) {
		return this.patterns.get(struct).size();
	}

	/**
	 * @return The number of occurrences of an access pattern.
	 */
	int getCount(Structure struct, AccessPattern pattern) {
		return this.patterns.get(struct).count(pattern);
	}

	/**
	 * @return The number of accesses we have to this field.
	 */
	private int getCount(DataTypeComponent field) {
		int count = 0;
		Multiset<AccessPattern> patterns = this.patterns.get(field.getParent());
		if (patterns != null) {
			for (Multiset.Entry<AccessPattern> entry : patterns.entrySet()) {
				if (entry.getElement().getFields().contains(field)) {
					count += entry.getCount();
				}
			}
		}
		return count;
	}

	/**
	 * @return The functions which had the given access pattern.
	 */
	Set<Function> getFunctions(AccessPattern pattern) {
		return this.functions.get(pattern);
	}

	/**
	 * Optimize the layout of a struct according to its access pattern.
	 */
	Structure optimize(Structure struct) {
		Set<DataTypeComponent> added = new HashSet<>();
		List<Bucket> buckets = new ArrayList<>();

		// Pack the most common access patterns first
		for (AccessPattern pattern : getPatterns(struct)) {
			Set<DataTypeComponent> fields = pattern.getFields();
			fields.removeAll(added);
			Bucket.pack(buckets, fields);
			added.addAll(fields);
		}

		// Add any missing fields we didn't see get accessed
		for (DataTypeComponent field : struct.getComponents()) {
			// Skip padding
			if (!field.getDataType().equals(DefaultDataType.dataType) && !added.contains(field)) {
				Bucket.pack(buckets, field);
			}
		}

		StructureDataType optimized = new StructureDataType(struct.getCategoryPath(), struct.getName(), 0, struct.getDataTypeManager());
		for (Bucket bucket : buckets) {
			for (DataTypeComponent field : bucket.getFields()) {
				optimized.add(field.getDataType(), field.getLength(), field.getFieldName(), field.getComment());
			}
		}
		return optimized;
	}

	/**
	 * Compute the cost of a structure reordering in our simple cache model.
	 */
	int score(Structure original, Structure struct) {
		int score = 0;

		for (AccessPattern pattern : getPatterns(original)) {
			Set<Integer> cacheLines = new HashSet<>();
			for (DataTypeComponent field : pattern.getFields()) {
				int start = 0;
				int end = 0;
				for (DataTypeComponent optField : struct.getComponents()) {
					if (field.getFieldName().equals(optField.getFieldName())) {
						start = field.getOffset();
						end = field.getEndOffset();
						break;
					}
				}
				for (int i = start / 64; i <= (end - 1) / 64; ++i) {
					cacheLines.add(i);
				}
			}

			score += getCount(original, pattern) * cacheLines.size();
		}

		return score;
	}
}

/**
 * A bucket of fields for structure optimization.
 */
class Bucket {
	/** Maximum one cache line. */
	private static final int MAX_SIZE = 64;

	private List<DataTypeComponent> fields;
	private int size;

	private Bucket(List<DataTypeComponent> fields) {
		this.fields = fields;
		this.size = sizeOf(fields);
	}

	List<DataTypeComponent> getFields() {
		return this.fields;
	}

	/**
	 * Add a field into a list of buckets.
	 */
	static void pack(List<Bucket> buckets, DataTypeComponent field) {
		pack(buckets, Collections.singletonList(field));
	}

	/**
	 * Add some fields into a list of buckets.
	 */
	static void pack(List<Bucket> buckets, Collection<DataTypeComponent> fields) {
		for (Bucket bucket : buckets) {
			if (bucket.tryAdd(fields)) {
				return;
			}
		}

		List<DataTypeComponent> fieldList = new ArrayList<>(fields);
		sort(fieldList);

		while (!fieldList.isEmpty()) {
			int i = 1;
			while (i < fieldList.size() && sizeOf(fieldList.subList(0, i + 1)) <= MAX_SIZE) {
				++i;
			}
			buckets.add(new Bucket(fieldList.subList(0, i)));
			fieldList = fieldList.subList(i, fieldList.size());
		}
	}

	/**
	 * Try to add some fields to this bucket.
	 *
	 * @return Whether the fields were successfully added.
	 */
	private boolean tryAdd(Collection<DataTypeComponent> fields) {
		List<DataTypeComponent> newFields = new ArrayList<>(this.fields);
		newFields.addAll(fields);
		sort(newFields);

		if (size == 0 || sizeOf(newFields) <= MAX_SIZE) {
			this.fields = newFields;
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Sort a sequence of fields to reduce holes.
	 */
	private static void sort(List<DataTypeComponent> fields) {
		// Sort by highest alignment first to reduce holes
		Collections.sort(fields, Comparator
			.<DataTypeComponent>comparingInt(f -> f.getDataType().getAlignment())
			.thenComparingInt(f -> f.getDataType().getLength())
			.reversed());
	}

	/**
	 * Compute the size of a sequence of fields.
	 */
	private static int sizeOf(List<DataTypeComponent> fields) {
		int size = 0;

		for (DataTypeComponent field : fields) {
			int align = field.getDataType().getAlignment();
			if (size % align != 0) {
				size += align - (size % align);
			}
			size += field.getDataType().getLength();
		}

		return size;
	}
}
