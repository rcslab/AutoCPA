import bcpi.AccessPattern;
import bcpi.AccessPatterns;
import bcpi.BcpiConfig;
import bcpi.BcpiControlFlow;
import bcpi.BcpiData;
import bcpi.BcpiDecompiler;
import bcpi.DataTypes;
import bcpi.Field;
import bcpi.FieldReferences;
import bcpi.Linker;
import bcpi.StructAbiConstraints;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import com.google.common.base.Throwables;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.SetMultimap;
import com.google.common.html.HtmlEscapers;

import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * An ABI constraint argument.
 */
interface ConstraintArg {
	String getType();

	void apply(StructAbiConstraints constraints);
}

/**
 * A field group constraint.
 */
class FieldGroupConstraint implements ConstraintArg {
	private static final Pattern PATTERN = Pattern.compile("(\\w+)::group\\((\\w+)\\)=(\\d+)");

	private final String type;
	private final String field;
	private final int group;

	private FieldGroupConstraint(String type, String field, int group) {
		this.type = type;
		this.field = field;
		this.group = group;
	}

	static Optional<FieldGroupConstraint> parse(String arg) {
		Matcher matcher = PATTERN.matcher(arg);
		if (!matcher.matches()) {
			return Optional.empty();
		}

		String type = matcher.group(1);
		String field = matcher.group(2);
		int group = Integer.parseInt(matcher.group(3));
		return Optional.of(new FieldGroupConstraint(type, field, group));
	}

	@Override
	public String getType() {
		return this.type;
	}

	@Override
	public void apply(StructAbiConstraints constraints) {
		constraints.setGroup(this.field, this.group);
	}
}

/**
 * A field range group constraint.
 */
class RangeGroupConstraint implements ConstraintArg {
	private static final Pattern PATTERN = Pattern.compile("(\\w+)::group\\((\\w+)-(\\w+)\\)=(\\d+)");

	private final String type;
	private final String first;
	private final String last;
	private final int group;

	private RangeGroupConstraint(String type, String first, String last, int group) {
		this.type = type;
		this.first = first;
		this.last = last;
		this.group = group;
	}

	static Optional<RangeGroupConstraint> parse(String arg) {
		Matcher matcher = PATTERN.matcher(arg);
		if (!matcher.matches()) {
			return Optional.empty();
		}

		String type = matcher.group(1);
		String first = matcher.group(2);
		String last = matcher.group(3);
		int group = Integer.parseInt(matcher.group(4));
		return Optional.of(new RangeGroupConstraint(type, first, last, group));
	}

	@Override
	public String getType() {
		return this.type;
	}

	@Override
	public void apply(StructAbiConstraints constraints) {
		constraints.setRangeGroup(this.first, this.last, this.group);
	}
}

/**
 * A relative group order constraint.
 */
class GroupOrderConstraint implements ConstraintArg {
	private static final Pattern PATTERN = Pattern.compile("(\\w+)::group\\((\\d+)\\)<group\\((\\d+)\\)");

	private final String type;
	private final int before;
	private final int after;

	private GroupOrderConstraint(String type, int before, int after) {
		this.type = type;
		this.before = before;
		this.after = after;
	}

	static Optional<GroupOrderConstraint> parse(String arg) {
		Matcher matcher = PATTERN.matcher(arg);
		if (!matcher.matches()) {
			return Optional.empty();
		}

		String type = matcher.group(1);
		int before = Integer.parseInt(matcher.group(2));
		int after = Integer.parseInt(matcher.group(3));
		return Optional.of(new GroupOrderConstraint(type, before, after));
	}

	@Override
	public String getType() {
		return this.type;
	}

	@Override
	public void apply(StructAbiConstraints constraints) {
		constraints.orderGroups(this.before, this.after);
	}
}

/**
 * A fixed field constraint.
 */
class FixedFieldConstraint implements ConstraintArg {
	private static final Pattern PATTERN = Pattern.compile("(\\w+)::fixed\\((\\w+)\\)=(\\d+)");

	private final String type;
	private final String field;
	private final int index;

	private FixedFieldConstraint(String type, String field, int index) {
		this.type = type;
		this.field = field;
		this.index = index;
	}

	static Optional<FixedFieldConstraint> parse(String arg) {
		Matcher matcher = PATTERN.matcher(arg);
		if (!matcher.matches()) {
			return Optional.empty();
		}

		String type = matcher.group(1);
		String field = matcher.group(2);
		int index = Integer.parseInt(matcher.group(3));
		return Optional.of(new FixedFieldConstraint(type, field, index));
	}

	@Override
	public String getType() {
		return this.type;
	}

	@Override
	public void apply(StructAbiConstraints constraints) {
		constraints.setFixed(this.field, this.index);
	}
}

/**
 * Analyzes cache misses to suggest reorderings of struct fields.
 */
public class StructOrderAnalysis extends GhidraScript {
	private ListMultimap<String, ConstraintArg> constraints = ArrayListMultimap.create();

	@Override
	public void run() throws Exception {
		List<Program> programs = getAllPrograms();

		// Read address_info.csv to find relevant addresses
		String[] args = getScriptArgs();
		Path csv = Paths.get(args[0]);
		BcpiData data = BcpiData.parse(csv, programs);

		// Process command line arguments
		for (int i = 1; i < args.length; ++i) {
			String arg = args[i];

			Optional<ConstraintArg> parsed = Optional.<ConstraintArg>empty()
				.or(() -> FieldGroupConstraint.parse(arg))
				.or(() -> RangeGroupConstraint.parse(arg))
				.or(() -> GroupOrderConstraint.parse(arg))
				.or(() -> FixedFieldConstraint.parse(arg));

			if (parsed.isPresent()) {
				ConstraintArg constraint = parsed.get();
				this.constraints.put(constraint.getType(), constraint);
			} else {
				Msg.error(this, "Unsupported command line argument " + arg);
				return;
			}
		}

		// Get the decompilation of each function containing an address
		// for which we have data.  This is much faster than calling
		// DataTypeReferenceFinder once per field.
		Linker linker = new Linker(programs);

		BcpiControlFlow cfgs = new BcpiControlFlow(linker);
		cfgs.addCoverage(data);

		Set<Function> funcs = cfgs.getCalledFunctions(data.getFunctions(), BcpiConfig.IPA_DEPTH);
		BcpiDecompiler decomp = new BcpiDecompiler();
		decomp.decompile(funcs);

		FieldReferences refs = new FieldReferences(decomp);
		refs.collect(funcs);

		// Use our collected data to infer field access patterns
		AccessPatterns patterns = new AccessPatterns(linker, cfgs, refs);
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
			DomainObject object = file.getDomainObject(this, true, false, this.monitor);
			if (object instanceof Program) {
				programs.add((Program) object);
			}
		}

		for (DomainFolder subFolder : folder.getFolders()) {
			getAllPrograms(subFolder, programs);
		}
	}

	/**
	 * Sanitize a struct name for a file path.
	 */
	private static String sanitizeFileName(String name) {
		String result = name.replaceAll("\\W", "");

		if (result.length() > 32) {
			result = result.substring(0, 32);
		}

		if (!result.equals(name)) {
			result += "_" + Integer.toHexString(name.hashCode());
		}

		return result;
	}

	/**
	 * HTML-escape a string.
	 */
	private static String htmlEscape(String string) {
		return HtmlEscapers.htmlEscaper().escape(string);
	}

	/**
	 * Simple syntax highlighting for a line of code.
	 */
	private static String syntaxHighlight(String code) {
		code = htmlEscape(code);
		code = code.replaceAll("\\bstruct\\b", "<strong>struct</strong>");
		code = code.replaceAll("\\bunion\\b", "<strong>union</strong>");
		return code;
	}

	/**
	 * Add a span start tag if a comment is found.
	 */
	private static boolean highlightComment(StringBuilder code) {
		int i = code.indexOf("//");
		if (i >= 0) {
			code.insert(i, "<span class='comment'>");
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Calculate a percentage without dividing by zero.
	 */
	private static int percent(long amount, long total) {
		if (total == 0) {
			return 0;
		} else {
			return (int) (100 * amount / total);
		}
	}

	/**
	 * A row in the index.html table.
	 */
	private static class IndexRow {
		final String name;
		final String href;
		final int nSamples;
		final long cost;
		int costPercent = 0;
		final long improvement;
		int cumulative = 0;

		IndexRow(String name, String href, int nSamples, long cost, long improvement) {
			this.name = name;
			this.href = href;
			this.nSamples = nSamples;
			this.cost = cost;
			this.improvement = improvement;
		}

		@Override
		public String toString() {
			String name = this.name;
			if (name.length() > 32) {
				name = name.substring(0, 32) + "...";
			}
			name = htmlEscape(name);

			return new StringBuilder()
				.append("<tr>")
				.append("<td><a href='").append(href).append("'><code>").append(name).append("</code></a></td>")
				.append("<td style='text-align: right;'>").append(String.format("%,d", nSamples)).append("</td>")
				.append("<td style='text-align: right;'>").append(String.format("%d%%", costPercent)).append("</td>")
				.append("<td style='text-align: right;'>").append(String.format("%,d", improvement)).append("</td>")
				.append("<td style='text-align: right;'>").append(String.format("%d%%", cumulative)).append("</td>")
				.append("</tr>")
				.toString();
		}
	}

	/**
	 * Render all structures to HTML.
	 */
	private void render(AccessPatterns patterns, Path results) throws Exception {
		Msg.info(this, String.format("Optimizing %,d structures", patterns.getStructures().size()));

		Path structResults = results.resolve("structs");
		Files.createDirectories(structResults);

		List<IndexRow> rows = patterns.getStructures()
			.parallelStream()
			.map(struct -> {
                                String name = struct.getName();

				StructAbiConstraints constraints = new StructAbiConstraints(struct);
				for (ConstraintArg arg : this.constraints.get(name)) {
					arg.apply(constraints);
				}

				Structure optimized = CostModel.optimize(patterns, struct, constraints);

				Path path = structResults.resolve(sanitizeFileName(name) + ".html");
				renderStructs(struct, optimized, patterns, path);

				int nSamples = patterns.getPatterns(struct)
					.stream()
					.mapToInt(pattern -> patterns.getCount(struct, pattern))
					.sum();

				String text = DataTypes.formatCDecl(struct);
				String href = results.relativize(path).toString();
				long before = CostModel.score(patterns, struct, struct);
				long after = CostModel.score(patterns, struct, optimized);
				long improvement = before - after;
				return new IndexRow(text, href, nSamples, before, improvement);
			})
			.sorted(Comparator
				.<IndexRow>comparingLong(row -> -row.improvement)
				.thenComparing(row -> row.name))
			.collect(Collectors.toList());

		long totalCost = rows
			.stream()
			.mapToLong(row -> row.cost)
			.sum();
		long totalImprovement = rows
			.stream()
			.mapToLong(row -> Math.max(0, row.improvement))
			.sum();

		long cumulative = 0;
		for (IndexRow row : rows) {
			cumulative += Math.max(0, row.improvement);
			row.cumulative = percent(cumulative, totalImprovement);
			row.costPercent = percent(row.cost, totalCost);
		}

		Path index = results.resolve("index.html");
		try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(index))) {
			out.println("<!DOCTYPE html>");
			out.println("<html>");

			out.println("<head>");
			String projectName = getState().getProject().getName();
			out.println("<title>" + projectName + " - BCPI</title>");
			out.println("</head>");

			out.println("<body style='max-width: 750px; margin: 0 auto;'>");

			out.format("<p style='float: left;'><strong>Total cost:</strong> %,d</p>\n", totalCost);

			long percentage = percent(cumulative, totalCost);
			out.format("<p style='float: right;'><strong>Possible improvement:</strong> %,d (%,d%%)</p>\n", cumulative, percentage);

			out.println("<table style='width: 100%; border-collapse: collapse; clear: both;'>");
			out.println("<thead>");
			out.println("<tr style='font-weight: bold;'>");
			out.println("<th style='text-align: left;'>Structure</th>");
			out.println("<th style='text-align: right;'>Samples</th>");
			out.println("<th style='text-align: right;'>Share of cost</th>");
			out.println("<th style='text-align: right;'>Improvement</th>");
			out.println("<th style='text-align: right;'>Cumulative</th>");
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

		Msg.info(this, "Results available in " + index.toAbsolutePath());
	}

	/**
	 * Render the pre- and post-optimization structure layouts to HTML.
	 */
	private void renderStructs(Structure before, Structure after, AccessPatterns patterns, Path path) {
		try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(path))) {
			out.println("<!DOCTYPE html>");
			out.println("<html>");

			out.println("<head>");
			String structName = htmlEscape(before.getName());
			String projectName = getState().getProject().getName();
			out.println("<title>struct " + structName + " - " + projectName + " - BCPI</title>");
			out.println("<style>");
			out.println("body {");
			out.println("    margin: 0;");
			out.println("}");
			out.println(".column {");
			out.println("    padding: 0 8px;");
			out.println("    max-height: 100vh;");
			out.println("    overflow-y: scroll;");
			out.println("}");
			out.println(".pattern ul {");
			out.println("    columns: 2;");
			out.println("    column-fill: auto;");
			out.println("    max-height: 120px;");
			out.println("    overflow: scroll;");
			out.println("}");
			out.println(".field-ellipsis {");
			out.println("    display: inline-block;");
			out.println("    vertical-align: bottom;");
			out.println("    max-width: 80ch;");
			out.println("    overflow: hidden;");
			out.println("    text-overflow: ellipsis;");
			out.println("}");
			out.println(".pattern, .field {");
			out.println("    cursor: default;");
			out.println("}");
			out.println(".highlight, .highlight-sticky {");
			out.println("    background-color: lavender;");
			out.println("    transition: all 0.2s;");
			out.println("}");
			out.println(".highlight-sticky {");
			out.println("    background-color: thistle;");
			out.println("}");
			out.println("pre .highlight, pre .highlight-sticky {");
			out.println("    font-weight: bold;");
			out.println("}");
			out.println(".comment {");
			out.println("    color: darkslateblue;");
			out.println("}");
			out.println("</style>");
			out.println("<script>");
			out.println("function highlight(selector, sticky, force) {");
			out.println("    const className = sticky ? 'highlight-sticky' : 'highlight'");
			out.println("    document.querySelectorAll(selector)");
			out.println("        .forEach(e => e.classList.toggle(className, force));");
			out.println("}");
			out.println("function highlightSticky(element, selector) {");
			out.println("    let force = !element.classList.contains('highlight-sticky');");
			out.println("    highlight('.highlight-sticky', true, false);");
			out.println("    highlight(selector, true, force);");
			out.println("}");
			out.println("</script>");
			out.println("</head>");

			out.println("<body>");
			out.println("<main style='display: grid; grid-template-columns: repeat(3, 1fr); grid-template-rows: auto; grid-column-gap: 8px;'>");

			out.println("<div class='column' style='grid-area: 1 / 1 / 2 / 2;'>");
			out.println("<p><strong>Access patterns:</strong></p>");
			renderAccessPatterns(before, patterns, out);
			out.println("</div>");

			out.println("<div class='column' style='grid-area: 1 / 2 / 2 / 3;'>");
			long beforeCost = CostModel.score(patterns, before, before);
			out.format("<p><strong>Before:</strong> %,d</p>\n", beforeCost);
			renderStruct(before, before, patterns, out);
			out.println("</div>");

			out.println("<div class='column' style='grid-area: 1 / 3 / 2 / 4;'>");
			long afterCost = CostModel.score(patterns, before, after);
			long improvement = afterCost - beforeCost;
			int percentage = percent(improvement, beforeCost);
			out.format("<p><strong>After:</strong> %,d (%+,d; %+d%%)</p>\n", afterCost, improvement, percentage);
			renderStruct(before, after, patterns, out);
			out.println("</div>");

			out.println("</main>");
			out.println("</body>");

			out.println("</html>");
		} catch (Exception e) {
			throw Throwables.propagate(e);
		}
	}

	/**
	 * Render a structure layout to HTML.
	 */
	private void renderStruct(Structure original, Structure struct, AccessPatterns patterns, PrintWriter out) {
		Table table = new Table();
		table.addColumn(); // Field type
		table.addColumn(); // Field name

		table.addRow();
		table.get(0, 0)
			.append(DataTypes.formatCDecl(struct))
			.append(" {");

		Map<String, Integer> fieldIds = Arrays.stream(original.getComponents())
			.filter(f -> !Field.isPadding(f))
			.collect(Collectors.toMap(f -> f.getFieldName(), f -> f.getOrdinal()));

		BiMap<String, Integer> rows = HashBiMap.create();
		int padding = 0;
		int lastCacheLine = -1;
		for (DataTypeComponent field : struct.getComponents()) {
			int cacheLine = field.getOffset() / 64;
			if (cacheLine != lastCacheLine) {
				addPadding(table, padding);
				padding = 0;
				lastCacheLine = cacheLine;

				int row = table.addRow();
				table.get(row, 0)
					.append("\t// Cache line ")
					.append(cacheLine);

				int offset = field.getOffset() % 64;
				if (offset != 0) {
					table.get(row, 1)
						.append("(offset ")
						.append(offset)
						.append(" bytes)");
				}
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

		// Correct alignment from
		//
		//     int x;
		//     int *y;
		//     int (*z)(...);
		//
		// to
		//
		//     int   x;
		//     int  *y;
		//     int (*z)(...);
		int nameCol = 0;
		for (String name : rows.keySet()) {
			int row = rows.get(name);
			StringBuilder decl = table.get(row, 1);
			nameCol = Math.max(nameCol, decl.indexOf(name));
		}
		for (int row = 0; row < table.nRows(); ++row) {
			StringBuilder decl = table.get(row, 1);
			int spaces = nameCol;
			String name = rows.inverse().get(row);
			if (name != null) {
				spaces -= decl.indexOf(name);
			}
			decl.insert(0, " ".repeat(spaces));
		}

		int commentCol = table.addColumn();
		table.get(0, commentCol).append("//");
		for (int row : rows.values()) {
			table.get(row, commentCol).append("//");
		}

		Set<AccessPattern> structPatterns = patterns.getPatterns(original);
		SetMultimap<String, Integer> fieldPatterns = HashMultimap.create();
		SetMultimap<Integer, Integer> colPatterns = HashMultimap.create();
		int count = 0;
		int total = patterns.getCount(original);
		final int MAX_COLS = 7;
		for (AccessPattern pattern : structPatterns) {
			int patternId = count++;

			int col = MAX_COLS;
			if (col >= table.nColumns()) {
				col = table.addColumn();
			}
			colPatterns.put(col, patternId);

			if (col < MAX_COLS) {
				int percentage = percent(patterns.getCount(original, pattern), total);
				table.get(0, col)
					.append(percentage)
					.append("%");
			} else {
				table.get(0, col)
					.replace(0, 3, "...");
			}

			for (Field field : pattern.getFields()) {
				boolean read = pattern.getReadFields().contains(field);
				boolean written = pattern.getWrittenFields().contains(field);

				for (DataTypeComponent component : field.getComponents()) {
					String name = component.getFieldName();
					fieldPatterns.put(name, patternId);

					StringBuilder str = table.get(rows.get(name), col);
					if (col < MAX_COLS) {
						str.append(read ? "R" : " ");
						str.append(written ? "W" : " ");
					} else {
						str.replace(0, 3, "...");
					}
				}
			}
		}

		Map<Integer, String> colClasses = new HashMap<>();
		for (int col : colPatterns.keySet()) {
			table.pad(col);

			colClasses.put(col, colPatterns.get(col)
				.stream()
				.sorted()
				.map(i -> "pattern-" + i)
				.collect(Collectors.joining(" ")));
		}

		table.align();

		int typeWidth = table.columnWidth(0) + 1;
		table.overflow(2, 80);

		for (int row = 0; row < table.nRows(); ++row) {
			String field = rows.inverse().get(row);

			StringBuilder typeCell = table.get(row, 0);
			boolean comment = highlightComment(typeCell);
			if (!comment) {
				String origType = typeCell.toString();
				typeCell.setLength(0);
				typeCell.append(syntaxHighlight(origType));

				// If the field type is a known struct, link it
				if (field != null) {
					DataTypeComponent component = original.getComponent(fieldIds.get(field));
					DataType type = DataTypes.undecorate(component.getDataType());
					type = DataTypes.resolve(type);
					type = DataTypes.dedup(type);
					if (patterns.getStructures().contains(type)) {
						String href = sanitizeFileName(type.getName());
						typeCell.insert(1, "<a href='" + href + ".html'>")
							.append("</a>");
					}
				}

				StringBuilder declCell = table.get(row, 1);
				if (typeWidth + declCell.length() > 80) {
					String span = String.format("<span class='field-ellipsis' title='%s %s'>", origType.strip(), declCell.toString().strip());
					typeCell.insert(0, span);
					declCell.append("</span>");
				}

				comment = highlightComment(table.get(row, commentCol));
			}

			for (int col : colPatterns.keySet()) {
				StringBuilder cell = table.get(row, col);
				String classes = colClasses.get(col);
				cell.insert(0, "<span class='" + classes + "'>")
					.append("</span>");
			}

			if (comment) {
				table.get(row, table.nColumns() - 1)
					.append("</span>");
			}

			if (field != null) {
				int id = fieldIds.get(field);
				String classes =
					Stream.concat(
						Stream.of("field", "field-" + id),
						fieldPatterns.get(field)
							.stream()
							.sorted()
							.map(i -> "pattern-" + i)
					)
					.collect(Collectors.joining(" "));
				String selector =
					Stream.concat(
						Stream.of(".field-" + id),
						fieldPatterns.get(field)
							.stream()
							.sorted()
							.map(i -> ".pattern.pattern-" + i)
					)
					.collect(Collectors.joining(", "));

				String tag = String.format("<span class='%s'", classes);
				tag += String.format(" onmouseenter=\"highlight('%s', false, true);\"", selector);
				tag += String.format(" onmouseleave=\"highlight('%s', false, false);\"", selector);
				tag += String.format(" onclick=\"highlightSticky(this, '%s');\">", selector);
				table.get(row, 0)
					.insert(0, tag);
				table.get(row, table.nColumns() - 1)
					.append("</span>");
			}
		}

		out.println("<pre>");

		out.print(table);
		out.println("};");

		if (struct != original) {
			out.println();
			out.print("<div class='comment' style='overflow-x: scroll;'>");
			out.println("/*");
			out.println();

			out.println("clang-reorder-fields command:");
			out.println();

			String fields = Arrays.stream(struct.getComponents())
				.filter(f -> !Field.isPadding(f))
				.map(f -> f.getFieldName())
				.collect(Collectors.joining(","));
			out.println("$ clang-reorder-fields \\");
			out.print("\t--record-name=");
			out.print(struct.getName());
			out.print(" \\\n\t--fields-order=");
			out.println(fields);

			out.println();
			out.println("Initializer macro:");
			out.println();

			String args = Arrays.stream(original.getComponents())
				.filter(f -> !Field.isPadding(f))
				.map(f -> f.getFieldName())
				.collect(Collectors.joining(", "));
			String body = Arrays.stream(original.getComponents())
				.filter(f -> !Field.isPadding(f))
				.map(f -> f.getFieldName())
				.collect(Collectors.joining(", "));
			out.print("#define INIT_");
			out.print(struct.getName());
			out.print("(");
			out.print(args);
			out.print(") \\\n\t");
			out.println(body);

			out.println();
			out.print("*/</div>");
		}

		out.println("</pre>");
	}

	private int addField(Table table, DataTypeComponent field) {
		int row = table.addRow();
		StringBuilder declarator = table.get(row, 0);
		StringBuilder specifier = table.get(row, 1);
		DataTypes.formatCDecl(field.getDataType(), field.getFieldName(), declarator, specifier);
		declarator.insert(0, "\t");
		specifier.append(";");
		return row;
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
		int id = 0;
		for (AccessPattern pattern : structPatterns) {
			out.format("<li class='pattern pattern-%d' style='margin-top: 8px;'", id);
			out.format(" onmouseenter=\"highlight('.pattern-%d', false, true);\"", id);
			out.format(" onmouseleave=\"highlight('.pattern-%d', false, false);\"", id);
			out.format(" onclick=\"highlightSticky(this, '.pattern-%d');\">", id);

			int count = patterns.getCount(struct, pattern);
			int percentage = percent(count, total);
			out.format("%d%% (%,d times)<br><code>%s</code>\n", percentage, count, pattern);

			out.println("<ul>");
			patterns.getFunctions(pattern)
				.stream()
				.map(f -> f.getName())
				.sorted()
				.forEach(f -> out.format("<li><code>%s()</code>\n", f));
			out.println("</ul>");

			++id;
		}

		out.println("</ul>");
	}
}

/**
 * A properly aligned table.
 */
class Table {
	private final List<List<StringBuilder>> rows = new ArrayList<>();
	private List<int[]> padding;
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
	 * @return The amount of padding for the given cell.
	 */
	private int getPadding(int row, int col) {
		return this.padding.get(row)[col];
	}

	/**
	 * @return The width of a column of text, taking leading tabs into account.
	 */
	private static int width(CharSequence string) {
		return string.codePoints()
			.map(c -> c == '\t' ? 8 : 1)
			.sum();
	}

	/**
	 * @return The width of the given column.
	 */
	int columnWidth(int col) {
		return this.rows
			.stream()
			.map(row -> row.get(col))
			.mapToInt(cell -> width(cell))
			.max()
			.orElse(0);
	}

	/**
	 * Explicitly pad a column with spaces.
	 */
	void pad(int col) {
		int colWidth = columnWidth(col);

		this.rows
			.stream()
			.map(row -> row.get(col))
			.forEach(cell -> cell.append(" ".repeat(colWidth - width(cell))));
	}

	/**
	 * Compute and cache padding to align each column.
	 */
	void align() {
		int[] widths = IntStream.range(0, this.nCols)
			.map(col -> columnWidth(col))
			.toArray();

		this.padding = this.rows
			.stream()
			.map(row -> IntStream.range(0, this.nCols)
				.map(col -> widths[col] - width(row.get(col)))
				.toArray())
			.collect(Collectors.toList());
	}

	/**
	 * Set a maximum width for the columns up to the given one.
	 */
	void overflow(int column, int width) {
		int prev = IntStream.range(0, column)
			.map(col -> columnWidth(col) + 1)
			.sum() - 1;

		if (prev > width) {
			int shift = prev - width;
			int i = column - 1;
			for (int[] pad : this.padding) {
				pad[i] = Math.max(0, pad[i] - shift);
			}
		}
	}

	/**
	 * @return The given line of the table.
	 */
	private String line(int row) {
		return IntStream.range(0, this.nCols)
			.mapToObj(col -> get(row, col).toString() + " ".repeat(getPadding(row, col)))
			.collect(Collectors.joining(" "))
			.stripTrailing();
	}

	/**
	 * @return The lines of the table.
	 */
	Stream<String> lines() {
		return IntStream.range(0, nRows())
			.mapToObj(row -> line(row));
	}

	@Override
	public String toString() {
		return this
			.lines()
			.collect(Collectors.joining("\n", "", "\n"));
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
	static Structure optimize(AccessPatterns patterns, Structure struct, StructAbiConstraints constraints) {
		List<Field> origFields = Field.allFields(struct);
		List<Field> fields = new ArrayList<>();
		Set<Field> added = new HashSet<>();

		// Add fields with fixed positions first
		for (Field field : origFields) {
			if (constraints.isFixed(field)) {
				pack(patterns, struct, fields, field, constraints);
				added.add(field);
			}
		}

		// Then access patterns from most common to least
		for (AccessPattern pattern : patterns.getPatterns(struct)) {
			pattern.getFields()
				.stream()
				.filter(f -> !added.contains(f))
				.sorted(Comparator.comparingInt(f -> f.getOrdinal()))
				.forEach(f -> pack(patterns, struct, fields, f, constraints));

			added.addAll(pattern.getFields());
		}

		// Add any missing fields we didn't see
		for (Field field : origFields) {
			if (!added.contains(field)) {
				pack(patterns, struct, fields, field, constraints);
			}
		}

		return build(struct, fields);
	}

	/**
	 * Pack a new field into a structure.
	 */
	private static void pack(AccessPatterns patterns, Structure original, List<Field> fields, Field field, StructAbiConstraints constraints) {
		List<Field> copy = new ArrayList<>(fields);
		copy.add(field);

		int bestI = -1;
		long bestScore = -1;
		for (int i = copy.size() - 1; ; --i) {
			if (constraints.check(copy, i)) {
				long newScore = score(patterns, original, build(original, copy));
				if (bestI < 0 || newScore < bestScore) {
					bestI = i;
					bestScore = newScore;
				}
			}

			if (i == 0) {
				break;
			}
			Collections.swap(copy, i - 1, i);
		}

		if (bestI < 0) {
			throw new RuntimeException("Unsatisfiable constraints for field " + field);
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
