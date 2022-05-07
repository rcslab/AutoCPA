import bcpi.AccessPattern;
import bcpi.AccessPatterns;
import bcpi.BcpiConfig;
import bcpi.BcpiData;
import bcpi.BcpiDataRow;
import bcpi.ControlFlowGraph;
import bcpi.Field;
import bcpi.FieldReferences;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.SetMultimap;

import java.nio.file.Path;
import java.nio.file.Paths;
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

			int before = CostModel.score(patterns, struct, struct);
			int after = CostModel.score(patterns, struct, CostModel.optimize(patterns, struct));
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

			printAccessPatterns(patterns, struct);

			System.out.print("Original layout:\n\n");
			printStruct(patterns, struct, struct);
			int before = CostModel.score(patterns, struct, struct);

			Structure optimized = CostModel.optimize(patterns, struct);
			System.out.print("Suggested layout:\n\n");
			printStruct(patterns, struct, optimized);
			int after = CostModel.score(patterns, struct, optimized);

			System.out.format("Improvement: %d (before: %d, after: %d)\n", before - after, before, after);

			System.out.print("\n---\n");
		}
	}

	private void printAccessPatterns(AccessPatterns patterns, Structure struct) {
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
	}

	private void printStruct(AccessPatterns patterns, Structure original, Structure struct) {
		Table table = new Table();
		table.addColumn(); // Field type
		table.addColumn(); // Field name

		table.addRow();
		table.get(0, 0)
			.append("struct ")
			.append(struct.getName())
			.append(" {");

		Map<String, Integer> rows = new HashMap<>();
		int padding = 0;
		int lastCacheLine = -1;
		for (DataTypeComponent field : struct.getComponents()) {
			int cacheLine = field.getOffset() / 64;
			if (cacheLine != lastCacheLine) {
				int row = table.addRow();
				table.get(row, 0)
					.append("        // Cache line ")
					.append(cacheLine);
				lastCacheLine = cacheLine;
			}

			if (Field.isPadding(field)) {
				padding += field.getLength();
			} else {
				addPadding(table, padding);
				padding = 0;

				int row = addField(table, field);
				rows.put(field.getFieldName(), row);
			}
		}
		addPadding(table, padding);

		int commentCol = table.addColumn();
		table.get(0, commentCol).append("//");
		for (int row : rows.values()) {
			table.get(row, commentCol).append("//");
		}

		Set<AccessPattern> structPatterns = patterns.getPatterns(original);
		int total = patterns.getCount(original);
		int count = 0;
		for (AccessPattern pattern : structPatterns) {
			int col = table.addColumn();

			int percent = 100 * patterns.getCount(original, pattern) / total;
			table.get(0, col)
				.append(percent)
				.append("%");

			for (Field field : pattern.getFields()) {
				for (DataTypeComponent component : field.getComponents()) {
					if (!Field.isPadding(component)) {
						table.get(rows.get(component.getFieldName()), col).append("*");
					}
				}
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

		System.out.print(table);
		System.out.print("};\n\n");
	}

	private int addField(Table table, DataTypeComponent field) {
		DataType type = field.getDataType();

		List<Integer> dims = new ArrayList<>();
		while (type instanceof Array) {
			Array array = (Array) type;
			dims.add(array.getNumElements());
			type = array.getDataType();
		}

		int bitWidth = -1;
		if (type instanceof BitFieldDataType) {
			BitFieldDataType bitField = (BitFieldDataType) type;
			bitWidth = bitField.getDeclaredBitSize();
			type = bitField.getBaseDataType();
		}

		int row = table.addRow();

		StringBuilder typeName = table.get(row, 0)
			.append("        ");

		String specifier = getSpecifier(type);
		if (specifier != null) {
			typeName.append(specifier)
				.append(' ');
		}

		typeName.append(type.getName());

		StringBuilder name = table.get(row, 1);
		name.append(field.getFieldName());
		for (int dim : dims) {
			name.append("[")
				.append(dim)
				.append("]");
		}
		if (bitWidth >= 0) {
			name.append(": ")
				.append(bitWidth);
		}
		name.append(";");

		return row;
	}

	private String getSpecifier(DataType type) {
		while (type instanceof Pointer) {
			type = ((Pointer) type).getDataType();
		}

		if (type instanceof Structure) {
			return "struct";
		} else if (type instanceof Union) {
			return "union";
		} else if (type instanceof Enum) {
			return "enum";
		} else {
			return null;
		}
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
			StringBuilder line = new StringBuilder();

			for (int i = 0; i < this.nCols; ++i) {
				StringBuilder cell = row.get(i);
				line.append(cell);

				int width = widths.get(i);
				for (int j = cell.length(); j < width; ++j) {
					line.append(' ');
				}
			}

			result.append(line.toString().stripTrailing())
				.append('\n');
		}

		return result.toString();
	}
}

/**
 * A bucket of fields for structure optimization.
 */
class Bucket {
	/** Maximum one cache line. */
	private static final int MAX_SIZE = 64;

	private List<Field> fixed;
	private List<Field> fields;

	private Bucket(List<Field> fields) {
		this.fixed = new ArrayList<>();
		this.fields = ImmutableList.copyOf(fields);
	}

	/**
	 * @return The fields in this bucket.
	 */
	List<Field> getFields() {
		return ImmutableList.<Field>builder()
			.addAll(this.fixed)
			.addAll(this.fields)
			.build();
	}

	/**
	 * Add a fixed superclass to the buckets.
	 */
	static void addSuperClass(List<Bucket> buckets, Field field) {
		if (buckets.isEmpty()) {
			buckets.add(new Bucket(Collections.emptyList()));
		}
		buckets.get(0).fixed.add(field);
	}

	/**
	 * Add a field into a list of buckets.
	 */
	static void pack(List<Bucket> buckets, Field field) {
		pack(buckets, Collections.singletonList(field));
	}

	/**
	 * Add some fields into a list of buckets.
	 */
	static void pack(List<Bucket> buckets, Collection<Field> fields) {
		for (Bucket bucket : buckets) {
			if (bucket.tryAdd(fields)) {
				return;
			}
		}

		List<Field> fieldList = new ArrayList<>(fields);
		sort(fieldList);

		while (!fieldList.isEmpty()) {
			int i = 1;
			while (i < fieldList.size() && sizeOf(Collections.emptyList(), fieldList.subList(0, i + 1)) <= MAX_SIZE) {
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
	private boolean tryAdd(Collection<Field> fields) {
		List<Field> newFields = new ArrayList<>(this.fields);
		newFields.addAll(fields);
		sort(newFields);

		int slack = this.slack();
		int size = sizeOf(this.fixed, this.fields);
		int newSize = sizeOf(this.fixed, newFields);

		if (size == 0 || newSize - size <= slack) {
			this.fields = newFields;
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Sort a sequence of fields to reduce holes.
	 */
	private static void sort(List<Field> fields) {
		// Sort by highest alignment first to reduce holes
		Collections.sort(fields, Comparator
			.<Field>comparingInt(f -> -f.getDataType().getAlignment())
			.thenComparingInt(f -> -f.getDataType().getLength())
			.thenComparing(f -> f.getDataType().getName())
			.thenComparing(f -> f.getFieldName()));
	}

	/**
	 * Compute the size of a sequence of fields.
	 */
	private static int sizeOf(List<Field> fixed, List<Field> fields) {
		int size = 0;

		for (Field field : fixed) {
			int align = field.getDataType().getAlignment();
			if (size % align != 0) {
				size += align - (size % align);
			}
			size += field.getDataType().getLength();
		}

		for (Field field : fields) {
			int align = field.getDataType().getAlignment();
			if (size % align != 0) {
				size += align - (size % align);
			}
			size += field.getDataType().getLength();
		}

		return size;
	}

	/**
	 * Compute the amount of slack in this bucket.
	 */
	private int slack() {
		int size = sizeOf(this.fixed, this.fields);

		// If we exceed MAX_SIZE due to fixed/oversized fields, fill up to the next multiple
		int rem = size % MAX_SIZE;
		if (rem == 0 && size != 0) {
			return 0;
		} else {
			return MAX_SIZE - rem;
		}
	}
}

/**
 * The simplified cost model for our suggested optimizations.
 */
class CostModel {
	/**
	 * Optimize the layout of a struct according to its access pattern.
	 */
	static Structure optimize(AccessPatterns patterns, Structure struct) {
		Set<Field> added = new HashSet<>();
		List<Bucket> buckets = new ArrayList<>();

		// Add any missing fields we didn't see get accessed
		for (Field field : Field.allFields(struct)) {
			if (field.isSuperClass()) {
				Bucket.addSuperClass(buckets, field);
				added.add(field);
			}
		}

		// Pack the most common access patterns first
		for (AccessPattern pattern : patterns.getPatterns(struct)) {
			Set<Field> fields = new HashSet<>(pattern.getFields());
			fields.removeAll(added);
			Bucket.pack(buckets, fields);
			added.addAll(fields);
		}

		// Add any missing fields we didn't see get accessed
		for (Field field : Field.allFields(struct)) {
			if (!added.contains(field)) {
				Bucket.pack(buckets, field);
			}
		}

		StructureDataType optimized = new StructureDataType(struct.getCategoryPath(), struct.getName(), 0, struct.getDataTypeManager());
		buckets.stream()
			.flatMap(b -> b.getFields().stream())
			.forEach(f -> f.copyTo(optimized));
		return optimized;
	}

	/**
	 * Compute the cost of a structure reordering in our simple cache model.
	 */
	static int score(AccessPatterns patterns, Structure original, Structure struct) {
		int score = 0;

		for (AccessPattern pattern : patterns.getPatterns(original)) {
			Set<Integer> cacheLines = new HashSet<>();

			for (Field field : pattern.getFields()) {
				int start = 0;
				int end = 0;
				for (Field optField : Field.allFields(struct)) {
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

			score += patterns.getCount(original, pattern) * cacheLines.size();
		}

		return score;
	}
}
