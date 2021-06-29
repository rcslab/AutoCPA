import bcpi.BcpiConfig;
import bcpi.BcpiData;
import bcpi.BcpiDataRow;
import bcpi.ControlFlowGraph;
import bcpi.FieldReferences;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
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

import com.google.common.collect.HashMultimap;
import com.google.common.collect.HashMultiset;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Multiset;
import com.google.common.collect.Multisets;
import com.google.common.collect.SetMultimap;

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

/**
 * Analyzes cache misses to suggest reorderings of struct fields.
 */
public class StructOrderAnalysis extends GhidraScript {
	@Override
	public void run() throws Exception {
		List<Program> programs = getAllPrograms();

		// Read address_info.csv to find relevant addresses
		String[] args = getScriptArgs();
		Path csv = Paths.get(args[0]);
		BcpiData data = BcpiData.parse(csv, programs);

		// Get the decompilation of each function containing an address
		// for which we have data.  This is much faster than calling
		// DataTypeReferenceFinder once per field.
		SetMultimap<Program, Function> funcs = data.getRelevantFunctions(programs, this.monitor);
		FieldReferences refs = new FieldReferences();
		for (Program program : programs) {
			refs.collect(program, funcs.get(program), this.monitor);
		}

		// Use our collected data to infer field access patterns
		AccessPatterns patterns = AccessPatterns.collect(data, refs, this.monitor);
		Msg.info(this, "Found patterns for " + (100.0 * patterns.getHitRate()) + "% of samples");

		if (args.length > 1) {
			printDetails(patterns, args[1]);
		} else {
			printSummary(patterns);
		}
	}

	private List<Program> getAllPrograms() throws Exception {
		List<Program> programs = new ArrayList<>();
		getAllPrograms(getProjectRootFolder(), programs);
		return programs;
	}

	private void getAllPrograms(DomainFolder folder, List<Program> programs) throws Exception {
		for (DomainFile file : folder.getFiles()) {
			programs.add((Program) file.getDomainObject(this, true, false, this.monitor));
		}

		for (DomainFolder subFolder : folder.getFolders()) {
			getAllPrograms(subFolder, programs);
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
 * A set of fields accessed in a block.
 */
class AccessPattern {
	private final Set<DataTypeComponent> fields;

	AccessPattern(Set<DataTypeComponent> fields) {
		this.fields = ImmutableSet.copyOf(fields);
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
 * Struct field access patterns.
 */
class AccessPatterns {
	// Stores the access patterns for each struct
	private final Map<Structure, Multiset<AccessPattern>> patterns = new HashMap<>();
	private final SetMultimap<AccessPattern, Function> functions = HashMultimap.create();
	private final Map<Function, ControlFlowGraph> cfgs = new HashMap<>();
	private final BcpiData data;
	private final FieldReferences refs;
	private long samples = 0;
	private long attributed = 0;

	private AccessPatterns(BcpiData data, FieldReferences refs) {
		this.data = data;
		this.refs = refs;
	}

	/**
	 * Infer access patterns from the collected data.
	 */
	static AccessPatterns collect(BcpiData data, FieldReferences refs, TaskMonitor monitor) throws Exception {
		AccessPatterns patterns = new AccessPatterns(data, refs);
		patterns.collect(monitor);
		return patterns;
	}

	private void collect(TaskMonitor monitor) throws Exception {
		for (Address baseAddress : this.data.getAddresses()) {
			Map<Structure, Set<DataTypeComponent>> pattern = new HashMap<>();
			int count = this.data.getCount(baseAddress);

			Set<CodeBlock> blocks = getCodeBlocksThrough(baseAddress, monitor);
			for (CodeBlock block : blocks) {
				for (Address address : block.getAddresses(true)) {
					if (!BcpiConfig.ANALYZE_BACKWARD_FLOW && block.contains(baseAddress) && address.compareTo(baseAddress) < 0) {
						// Don't count accesses before the miss
						continue;
					}

					for (DataTypeComponent field : this.refs.getFields(address)) {
						Structure struct = (Structure) field.getParent();
						pattern.computeIfAbsent(struct, k -> new HashSet<>())
							.add(field);
					}
				}
			}

			this.samples += count;
			if (!pattern.isEmpty()) {
				this.attributed += count;
			}

			for (Map.Entry<Structure, Set<DataTypeComponent>> entry : pattern.entrySet()) {
				AccessPattern accessPattern = new AccessPattern(entry.getValue());
				this.patterns.computeIfAbsent(entry.getKey(), k -> HashMultiset.create())
					.add(accessPattern, count);
				this.functions.put(accessPattern, this.data.getRow(baseAddress).function);
			}
		}
	}

	/**
	 * @return The fraction of samples that we found an access pattern for.
	 */
	double getHitRate() {
		return (double) this.attributed / this.samples;
	}

	/**
	 * @return The cached CFG for a function.
	 */
	private ControlFlowGraph getCfg(Function function, TaskMonitor monitor) throws Exception {
		ControlFlowGraph cfg = this.cfgs.get(function);
		if (cfg == null) {
			cfg = new ControlFlowGraph(function, monitor);
			this.cfgs.put(function, cfg);
		}
		return cfg;
	}

	/**
	 * @return All the code blocks that flow through the given address.
	 */
	private Set<CodeBlock> getCodeBlocksThrough(Address address, TaskMonitor monitor) throws Exception {
		BcpiDataRow row = this.data.getRow(address);

		ControlFlowGraph cfg = getCfg(row.function, monitor);
		Set<CodeBlock> blocks = new HashSet<>(cfg.getLikelyReachedBlocks(address));
		Set<CodeBlock> prevBlocks = blocks;
		for (int i = 0; i < BcpiConfig.IPA_DEPTH; ++i) {
			Set<CodeBlock> calledBlocks = getCalledBlocks(prevBlocks, monitor);
			blocks.addAll(calledBlocks);
			prevBlocks = calledBlocks;
		}

		return blocks;
	}

	/**
	 * @return All the code blocks that are reached by function calls from the given blocks.
	 */
	private Set<CodeBlock> getCalledBlocks(Set<CodeBlock> blocks, TaskMonitor monitor) throws Exception {
		Set<CodeBlock> result = new HashSet<>();

		for (CodeBlock block : blocks) {
			CodeBlockReferenceIterator dests = block.getDestinations(monitor);
			while (dests.hasNext()) {
				CodeBlockReference dest = dests.next();
				if (!dest.getFlowType().isCall()) {
					continue;
				}

				CodeBlock destBlock = dest.getDestinationBlock();
				Address address = destBlock.getMinAddress();
				Function function = destBlock.getModel().getProgram().getListing().getFunctionContaining(address);
				if (function != null && function.isThunk()) {
					function = function.getThunkedFunction(true);
				}
				if (function == null) {
					continue;
				}

				long size = function.getBody().getNumAddresses();
				if (size <= 0 || size >= BcpiConfig.MAX_INLINE_SIZE) {
					continue;
				}

				ControlFlowGraph cfg = getCfg(function, monitor);
				result.addAll(cfg.getLikelyReachedBlocks(address));
			}
		}

		return result;
	}

	/**
	 * @return All the structures about which we have data.
	 */
	Set<Structure> getStructures() {
		return Collections.unmodifiableSet(this.patterns.keySet());
	}

	/**
	 * @return All the access patterns we saw for a structure, from most to least often.
	 */
	Set<AccessPattern> getPatterns(Structure struct) {
		return ImmutableSet.copyOf(
			Multisets.copyHighestCountFirst(this.patterns.get(struct))
				.elementSet()
		);
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
		return Collections.unmodifiableSet(this.functions.get(pattern));
	}

	/**
	 * Optimize the layout of a struct according to its access pattern.
	 */
	Structure optimize(Structure struct) {
		Set<DataTypeComponent> added = new HashSet<>();
		List<Bucket> buckets = new ArrayList<>();

		// Pack the most common access patterns first
		for (AccessPattern pattern : getPatterns(struct)) {
			Set<DataTypeComponent> fields = new HashSet<>(pattern.getFields());
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
					if (Objects.equals(field.getFieldName(), optField.getFieldName())) {
						start = optField.getOffset();
						end = optField.getEndOffset();
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
		this.fields = ImmutableList.copyOf(fields);
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
