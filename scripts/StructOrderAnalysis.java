import bcpi.AccessPattern;
import bcpi.AccessPatterns;
import bcpi.BcpiConfig;
import bcpi.BcpiControlFlow;
import bcpi.BcpiData;
import bcpi.BcpiDecompiler;
import bcpi.DataTypes;
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
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

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
		BcpiControlFlow cfgs = new BcpiControlFlow();
		cfgs.addCoverage(data);

		Set<Function> funcs = cfgs.getCalledFunctions(data.getFunctions(), BcpiConfig.IPA_DEPTH);
		BcpiDecompiler decomp = new BcpiDecompiler();
		decomp.decompile(funcs);

		FieldReferences refs = new FieldReferences(decomp);
		refs.collect(funcs);

		// Use our collected data to infer field access patterns
		AccessPatterns patterns = new AccessPatterns(cfgs, refs);
		patterns.collect(data);
		double hitRate = 100.0 * patterns.getHitRate();
		Msg.info(this, String.format("Found patterns for %.2f%% of samples", hitRate));

		String name = getState().getProject().getName();
		Path results = Paths.get("./results").resolve(name);
		render(patterns, results);
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

	/**
	 * A row in the index.html table.
	 */
	private static class IndexRow {
		final String name;
		final String href;
		final int nSamples;
		final int nPatterns;
		final long improvement;

		IndexRow(String name, String href, int nSamples, int nPatterns, long improvement) {
			this.name = name;
			this.href = href;
			this.nSamples = nSamples;
			this.nPatterns = nPatterns;
			this.improvement = improvement;
		}

		@Override
		public String toString() {
			return new StringBuilder()
				.append("<tr>")
				.append("<td><a href=\"").append(href).append("\"><code>struct ").append(name).append("</code></a></td>")
				.append("<td style=\"text-align: right;\">").append(String.format("%,d", nSamples)).append("</td>")
				.append("<td style=\"text-align: right;\">").append(String.format("%,d", nPatterns)).append("</td>")
				.append("<td style=\"text-align: right;\">").append(String.format("%,d", improvement)).append("</td>")
				.append("</tr>")
				.toString();
		}
	}

	/**
	 * Render all structures to HTML.
	 */
	private void render(AccessPatterns patterns, Path results) throws Exception {
		Path structResults = results.resolve("structs");
		Files.createDirectories(structResults);

		List<IndexRow> rows = new ArrayList<>();
		for (Structure struct : patterns.getStructures()) {
			String name = struct.getName();
			Structure optimized = CostModel.optimize(patterns, struct);

			Path path = structResults.resolve(name + ".html");
			renderStructs(struct, optimized, patterns, path);

			int nSamples = 0;
			int nPatterns = 0;
			for (AccessPattern pattern : patterns.getPatterns(struct)) {
				nSamples += patterns.getCount(struct, pattern);
				nPatterns += 1;
			}

			String href = results.relativize(path).toString();
			long before = CostModel.score(patterns, struct, struct);
			long after = CostModel.score(patterns, struct, optimized);
			long improvement = before - after;
			rows.add(new IndexRow(name, href, nSamples, nPatterns, improvement));
		}

		Collections.sort(rows, Comparator
			.<IndexRow>comparingLong(r -> -r.improvement)
			.thenComparing(r -> r.name));

		Path index = results.resolve("index.html");
		try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(index))) {
			out.println("<!DOCTYPE html>");
			out.println("<html>");

			out.println("<head>");
			String projectName = getState().getProject().getName();
			out.println("<title>" + projectName + " - BCPI</title>");
			out.println("</head>");

			out.println("<body style=\"max-width: 750px; margin: 0 auto;\">");
			out.println("<table style=\"width: 100%;\">");
			out.println("<thead>");
			out.println("<tr style=\"font-weight: bold;\">");
			out.println("<td>Structure</td>");
			out.println("<td style=\"text-align: right;\">Samples</td>");
			out.println("<td style=\"text-align: right;\">Access patterns</td>");
			out.println("<td style=\"text-align: right;\">Improvement</td>");
			out.println("</tr>");
			out.println("</thead>");
			out.println("<tbody>");

			for (IndexRow row : rows) {
				out.println(row);
			}

			out.println("</tbody>");
			out.println("</table>");
			out.println("</body>");

			out.println("</html>");
		}

		System.out.println("Results available in " + index);
	}

	/**
	 * Render the pre- and post-optimization structure layouts to HTML.
	 */
	private void renderStructs(Structure before, Structure after, AccessPatterns patterns, Path path) throws Exception {
		try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(path))) {
			out.println("<!DOCTYPE html>");
			out.println("<html>");

			out.println("<head>");
			String projectName = getState().getProject().getName();
			out.println("<title>struct " + before.getName() + " - " + projectName + " - BCPI</title>");
			out.println("<style>");
			out.println("body {");
			out.println("    margin: 0;");
			out.println("}");
			out.println(".column {");
			out.println("    padding: 0 8px;");
			out.println("    max-height: 100vh;");
			out.println("    overflow-y: scroll;");
			out.println("}");
			out.println(".highlight {");
			out.println("    background-color: lightgray;");
			out.println("    transition: all 0.2s;");
			out.println("}");
			out.println("pre .highlight {");
			out.println("    font-weight: bold;");
			out.println("}");
			out.println("</style>");
			out.println("</head>");

			out.println("<body>");
			out.println("<main style=\"display: grid; grid-template-columns: repeat(3, 1fr); grid-template-rows: auto; grid-column-gap: 8px;\">");

			out.println("<div class=\"column\" style=\"grid-area: 1 / 1 / 2 / 2;\">");
			out.println("<p><strong>Access patterns:</strong></p>");
			renderAccessPatterns(before, patterns, out);
			out.println("</div>");

			out.println("<div class=\"column\" style=\"grid-area: 1 / 2 / 2 / 3;\">");
			out.println("<p><strong>Before:</strong></p>");
			renderStruct(before, before, patterns, out);
			out.println("</div>");

			out.println("<div class=\"column\" style=\"grid-area: 1 / 3 / 2 / 4;\">");
			out.println("<p><strong>After:</strong></p>");
			renderStruct(before, after, patterns, out);
			out.println("</div>");

			out.println("</main>");
			out.println("</body>");

			out.println("</html>");
		}
	}

	/**
	 * Render a structure layout to HTML.
	 */
	private void renderStruct(Structure original, Structure struct, AccessPatterns patterns, PrintWriter out) throws Exception {
		Table table = new Table();
		table.addColumn(); // Field type
		table.addColumn(); // Field name

		table.addRow();
		table.get(0, 0)
			.append("struct ")
			.append(struct.getName())
			.append(" {");

		Map<String, Integer> rows = new HashMap<>();
		Map<Integer, String> fields = new HashMap<>();
		int padding = 0;
		int lastCacheLine = -1;
		for (DataTypeComponent field : struct.getComponents()) {
			int cacheLine = field.getOffset() / 64;
			if (cacheLine != lastCacheLine) {
				addPadding(table, padding);
				padding = 0;

				int row = table.addRow();
				table.get(row, 0)
					.append("\t// Cache line ")
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
				fields.put(row, field.getFieldName());
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
				boolean read = pattern.getReadFields().contains(field);
				boolean written = pattern.getWrittenFields().contains(field);

				for (DataTypeComponent component : field.getComponents()) {
					StringBuilder str = table.get(rows.get(component.getFieldName()), col);
					str.append(read ? "R" : " ");
					str.append(written ? "W" : " ");
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

		out.println("<pre>");

		Iterable<String> lines = () -> table.toString().lines().iterator();
		int row = 0;
		for (String line : lines) {
			String field = fields.get(row);
			if (field != null) {
				out.format("<span class=\"field-%s\"", field);
				out.format(" onmouseenter=\"document.querySelectorAll('.field-%s').forEach(e => e.classList.add('highlight'));\"", field);
				out.format(" onmouseleave=\"document.querySelectorAll('.field-%s').forEach(e => e.classList.remove('highlight'));\">", field);
			}

			out.print(line);

			if (field != null) {
				out.print("</span>");
			}
			out.println();

			++row;
		}

		out.println("}");
		out.println("</pre>");
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
			.append("\t");

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
				.append("\t// char");
			table.get(row, 1)
				.append("padding[")
				.append(padding)
				.append("];");
		}
	}

	/**
	 * Render the list of access patterns for a structure to HTML.
	 */
	private void renderAccessPatterns(Structure struct, AccessPatterns patterns, PrintWriter out) {
		out.println("<ul>");

		int total = patterns.getCount(struct);
		Set<AccessPattern> structPatterns = patterns.getPatterns(struct);
		for (AccessPattern pattern : structPatterns) {
			String selector = pattern.getFields()
				.stream()
				.flatMap(f -> f.getComponents().stream())
				.map(c -> ".field-" + c.getFieldName())
				.collect(Collectors.joining(", "));

			out.format("<li style=\"margin-top: 8px;\"");
			out.format(" onmouseenter=\"[this, ...document.querySelectorAll('%s')].forEach(e => e.classList.add('highlight'));\"", selector);
			out.format(" onmouseleave=\"[this, ...document.querySelectorAll('%s')].forEach(e => e.classList.remove('highlight'));\">", selector);

			int count = patterns.getCount(struct, pattern);
			int percent = 100 * count / total;
			out.format("%d%% (%,d times)<br><code>%s</code>\n", percent, count, pattern);

			out.println("<ul>");
			for (Function func : patterns.getFunctions(pattern)) {
				out.format("<li><code>%s()</code>\n", func.getName());
			}
			out.println("</ul>");
		}

		out.println("</ul>");
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

	/**
	 * @return The width of a column of text, taking leading tabs into account.
	 */
	private static int width(CharSequence string) {
		return string.codePoints()
			.map(c -> c == '\t' ? 8 : 1)
			.sum();
	}

	@Override
	public String toString() {
		List<Integer> widths = new ArrayList<>();
		for (int i = 0; i < this.nCols; ++i) {
			int width = 0;
			for (List<StringBuilder> row : this.rows) {
				int curWidth = Table.width(row.get(i));
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
				for (int j = Table.width(cell); j < width; ++j) {
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
 * The cost model for our suggested optimizations.
 */
class CostModel {
	private static final int CACHE_LINE = 64;

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
		long bestScore = -1;
		for (int i = copy.size() - 1; i >= minIndex; --i) {
			long newScore = score(patterns, original, build(original, copy));
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

		// Add trailing padding
		int align = DataTypes.getAlignment(original);
		int slop = align - (optimized.getLength() % align);
		if (slop != align) {
			optimized.add(DefaultDataType.dataType, slop);
		}

		return optimized;
	}

	/**
	 * Compute the cost of a structure reordering in our cost model.
	 */
	static long score(AccessPatterns patterns, Structure original, Structure optimized) {
		int align;
		if (BcpiConfig.ASSUME_CACHE_ALIGNED) {
			align = CACHE_LINE;
		} else {
			// Structures are not necessarily allocated at the beginning of a cache line
			align = DataTypes.getAlignment(original);
			// Assume allocations are at least pointer-aligned
			align = Math.max(align, original.getDataOrganization().getDefaultPointerAlignment());
			align = Math.min(align, CACHE_LINE);
		}

		// Compute a fast mapping between the original and optimized fields, since the
		// access patterns refer to the original fields
		List<Field> originalFields = Field.allFields(original);
		List<Field> optimizedFields = Field.allFields(optimized);
		Map<String, Field> fieldMap = optimizedFields
			.stream()
			.collect(Collectors.toMap(f -> f.getFieldName(), f -> f));

		Field[] fieldPerm = new Field[original.getNumComponents()];
		for (Field origField : originalFields) {
			Field optField = fieldMap.get(origField.getFieldName());
			fieldPerm[origField.getOrdinal()] = optField;
		}

		// As a heuristic, assume offset zero is twice as likely as the next possible
		// offset, which is twice as likely as the next one, etc.
		int nOffsets = CACHE_LINE / align;
		long totalWeight = (1L << nOffsets) - 1;

		// Compute the expected cost over the possible cache line offsets
		long total = 0;
		int weightShift = nOffsets;
		int nCacheLines = 1 + (optimized.getLength() + CACHE_LINE - 1) / CACHE_LINE;
		BitSet touchedLines = new BitSet(nCacheLines);
		for (int offset = 0; offset < CACHE_LINE; offset += align) {
			// For each offset, the cost is the cumulative number of cache lines touched
			// up to the current pattern, weighted by the pattern's observation count.
			// You can think of this like the area under the (pattern, cache lines) curve.
			touchedLines.clear();

			long cost = 0;
			for (AccessPattern pattern : patterns.getPatterns(original)) {
				long count = patterns.getCount(original, pattern);

				for (Field origField : pattern.getFields()) {
					Field optField = fieldPerm[origField.getOrdinal()];
					if (optField == null) {
						continue;
					}

					int start = (offset + optField.getOffset()) / CACHE_LINE;
					int end = (offset + optField.getEndOffset() - 1) / CACHE_LINE;
					touchedLines.set(start, end + 1);
				}

				cost += count * touchedLines.cardinality();
			}

			--weightShift;
			total += cost << weightShift;
		}

		// Normalize the score
		long cost = (total + totalWeight - 1) / totalWeight;

		// Penalize internal padding
		int padding = 0;
		for (DataTypeComponent field : optimized.getComponents()) {
			if (Field.isPadding(field)) {
				padding += field.getLength();
			} else {
				cost += padding;
				padding = 0;
			}
		}

		return cost;
	}
}
