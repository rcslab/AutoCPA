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
				addPadding(table, padding);
				padding = 0;

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
 * The simplified cost model for our suggested optimizations.
 */
class CostModel {
	/**
	 * Optimize the layout of a struct according to its access pattern.
	 */
	static Structure optimize(AccessPatterns patterns, Structure struct) {
		List<Field> fields = new ArrayList<>();
		Set<Field> added = new HashSet<>();

		// Add superclass fields with fixed positions
		for (Field field : Field.allFields(struct)) {
			if (field.isSuperClass()) {
				fields.add(field);
				added.add(field);
			}
		}
		int minIndex = fields.size();

		// Pack the most common access patterns first
		for (AccessPattern pattern : patterns.getPatterns(struct)) {
			pattern.getFields()
				.stream()
				.filter(f -> !added.contains(f))
				.sorted(Comparator.comparingInt(f -> f.getOrdinal()))
				.forEach(f -> pack(patterns, struct, fields, f, minIndex));

			added.addAll(pattern.getFields());
		}

		// Add any missing fields we didn't see get accessed
		for (Field field : Field.allFields(struct)) {
			if (!added.contains(field)) {
				pack(patterns, struct, fields, field, minIndex);
			}
		}

		return build(struct, fields);
	}

	/**
	 * Pack a new field into a structure.
	 */
	private static void pack(AccessPatterns patterns, Structure original, List<Field> fields, Field field, int minIndex) {
		List<Field> copy = new ArrayList<>(fields);
		copy.add(field);

		int bestI = -1;
		int bestScore = -1;
		for (int i = copy.size() - 1; i >= minIndex; --i) {
			int newScore = score(patterns, original, build(original, copy));
			if (bestI < 0 || newScore < bestScore) {
				bestI = i;
				bestScore = newScore;
			}

			if (i > minIndex) {
				Collections.swap(copy, i - 1, i);
			}
		}

		fields.add(bestI, field);
	}

	/**
	 * Make a copy of a structure with reordered fields.
	 */
	private static Structure build(Structure original, List<Field> fields) {
		StructureDataType optimized = new StructureDataType(original.getCategoryPath(), original.getName(), 0, original.getDataTypeManager());
		for (Field field : fields) {
			field.copyTo(optimized);
		}
		return optimized;
	}

	/**
	 * Compute the cost of a structure reordering in our simple cache model.
	 */
	static int score(AccessPatterns patterns, Structure original, Structure optimized) {
		List<Field> optFields = Field.allFields(optimized);
		int score = 0;

		for (AccessPattern pattern : patterns.getPatterns(original)) {
			Set<Integer> cacheLines = new HashSet<>();

			for (Field field : pattern.getFields()) {
				optFields.stream()
					.filter(f -> f.getFieldName().equals(field.getFieldName()))
					.forEach(f -> {
						int start = f.getOffset();
						int end = f.getEndOffset();
						for (int i = start / 64; i <= (end - 1) / 64; ++i) {
							cacheLines.add(i);
						}
					});
			}

			score += patterns.getCount(original, pattern) * cacheLines.size();
		}

		// Penalize padding
		for (DataTypeComponent field : optimized.getComponents()) {
			if (Field.isPadding(field)) {
				score += field.getLength();
			}
		}

		return score;
	}
}
