import bcpi.AccessPattern;
import bcpi.AccessPatterns;
import bcpi.BcpiAnalysis;
import bcpi.BcpiConfig;
import bcpi.BcpiControlFlow;
import bcpi.BcpiData;
import bcpi.CacheCostModel;
import bcpi.FieldReferences;
import bcpi.Linker;
import bcpi.StructAbiConstraints;
import bcpi.StructLayoutOptimizer;
import bcpi.type.BcpiStruct;
import bcpi.type.BcpiType;
import bcpi.type.Field;
import bcpi.type.Layout;
import bcpi.util.Log;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import com.google.common.base.Throwables;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.SetMultimap;
import com.google.common.html.HtmlEscapers;

import java.io.PrintWriter;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
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
public class StructOrderAnalysis extends BcpiAnalysis {
	private ListMultimap<String, ConstraintArg> constraints = ArrayListMultimap.create();
	private final ConcurrentMap<BcpiType, Path> typePaths = new ConcurrentHashMap<>();
	private final Set<String> typeNames = ConcurrentHashMap.newKeySet();
	private Path resultsPath;
	private long time;

	private void timer(String msg) {
		long now = System.currentTimeMillis();
		Log.debug("%s took %,d ms", msg, now - time);
		this.time = now;
	}

	@Override
	protected void analyze(String[] args) throws Exception {
		long uptime = ManagementFactory.getRuntimeMXBean().getUptime();
		this.time = System.currentTimeMillis() - uptime;
		timer("Starting analysis");

		var ctx = getContext();

		// Read address_info.csv to find relevant addresses
		Path csv = Paths.get(args[0]);
		BcpiData data = BcpiData.parse(csv, ctx);
		timer("Parsing data");

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
				Log.error("Unsupported command line argument " + arg);
				return;
			}
		}

		// Get the decompilation of each function containing an address
		// for which we have data.  This is much faster than calling
		// DataTypeReferenceFinder once per field.
		Set<Function> funcs = data.getFunctions();

		BcpiControlFlow cfgs = new BcpiControlFlow(ctx);
		cfgs.addCoverage(data);
		timer("Adding coverage");

		FieldReferences refs = new FieldReferences(ctx, cfgs);
		refs.collect(funcs);
		timer("Computing data flow");

		// Use our collected data to infer field access patterns
		AccessPatterns patterns = new AccessPatterns(cfgs, refs);
		patterns.collect(data);
		double hitRate = 100.0 * patterns.getHitRate();
		Log.info("Found patterns for %.2f%% of samples", hitRate);
		timer("Collecting access patterns");

		String name = getState().getProject().getName();
		this.resultsPath = Paths.get("results").resolve(name);
		render(patterns);
		timer("Optimizing structures");
	}

	/**
	 * Sanitize a struct name for a file path.
	 */
	private static String sanitizeFileName(String name) {
		String result = name.replaceAll("\\W", "");

		if (result.length() > 32) {
			result = result.substring(0, 32);
		}

		return result;
	}

	/**
	 * Get the result path for a type.
	 */
	private Path getResultPath(BcpiType type) {
		var path = this.resultsPath.resolve("structs");

		return this.typePaths.computeIfAbsent(type, k -> {
			var name = sanitizeFileName(type.getName());
			if (this.typeNames.add(name)) {
				return path.resolve(name + ".html");
			}

			for (int i = 1; ; ++i) {
				var uniq = name + "_" + i;
				if (this.typeNames.add(uniq)) {
					return path.resolve(uniq + ".html");
				}
			}
		});
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
		final long nSamples;
		final long cost;
		int costPercent = 0;
		final long improvement;
		int cumulative = 0;

		IndexRow(String name, String href, long nSamples, long cost, long improvement) {
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
	private void render(AccessPatterns patterns) throws Exception {
		var structs = patterns.getStructs();
		Log.info("Optimizing %,d structures", structs.size());

		Path structResults = this.resultsPath.resolve("structs");
		Files.createDirectories(structResults);

		List<IndexRow> rows = structs
			.parallelStream()
			.map(struct -> {
				String name = struct.getName();

				var constraints = new StructAbiConstraints(struct);
				for (var arg : this.constraints.get(name)) {
					arg.apply(constraints);
				}

				var costModel = new CacheCostModel(patterns, struct);
				var optimizer = new StructLayoutOptimizer(patterns, struct, constraints, costModel);
				var optimized = optimizer.optimize();

				var path = getResultPath(struct);
				renderStruct(struct, optimized, patterns, path);

				String text = struct.toC();
				String href = this.resultsPath.relativize(path).toString();
				long nSamples = patterns.getCount(struct);
				long before = costModel.cost(struct.getLayout());
				long after = costModel.cost(optimized);
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

		Path index = this.resultsPath.resolve("index.html");
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

		Log.info("Results available in %s", index.toAbsolutePath());
	}

	/**
	 * Render the pre- and post-optimization structure layouts to HTML.
	 */
	private void renderStruct(BcpiStruct struct, Layout optimized, AccessPatterns patterns, Path path) {
		try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(path))) {
			out.println("<!DOCTYPE html>");
			out.println("<html>");

			out.println("<head>");
			String structName = htmlEscape(struct.getName());
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
			out.println(".pattern ul.functions {");
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
			renderAccessPatterns(struct, patterns, out);
			out.println("</div>");

			var costModel = new CacheCostModel(patterns, struct);
			out.println("<div class='column' style='grid-area: 1 / 2 / 2 / 3;'>");
			long beforeCost = costModel.cost(struct.getLayout());
			out.format("<p><strong>Before:</strong> %,d</p>\n", beforeCost);
			renderLayout(struct, struct.getLayout(), patterns, out);
			out.println("</div>");

			out.println("<div class='column' style='grid-area: 1 / 3 / 2 / 4;'>");
			long afterCost = costModel.cost(optimized);
			long improvement = afterCost - beforeCost;
			int percentage = percent(improvement, beforeCost);
			out.format("<p><strong>After:</strong> %,d (%+,d; %+d%%)</p>\n", afterCost, improvement, percentage);
			renderLayout(struct, optimized, patterns, out);
			out.println("</div>");

			out.println("</main>");
			out.println("</body>");

			out.println("</html>");
		} catch (Exception e) {
			Throwables.throwIfUnchecked(e);
			throw new RuntimeException(e);
		}
	}

	/**
	 * Render a structure layout to HTML.
	 */
	private void renderLayout(BcpiStruct struct, Layout layout, AccessPatterns patterns, PrintWriter out) {
		Table table = new Table();
		table.addColumn(); // Field type
		table.addColumn(); // Field name

		table.addRow();
		table.get(0, 0)
			.append(struct.toC())
			.append(" {");

		Map<String, Integer> fieldIds = layout
			.getFields()
			.stream()
			.collect(Collectors.toMap(f -> f.getName(), f -> f.getOriginalIndex()));

		BiMap<String, Integer> rows = HashBiMap.create();
		int lastByte = 0;
		int lastCacheLine = -1;
		for (var field : layout.getFields()) {
			int startByte = field.getStartByte();
			addPadding(table, startByte - lastByte);
			lastByte = field.getEndByte();

			int cacheLine = startByte / 64;
			if (cacheLine != lastCacheLine) {
				lastCacheLine = cacheLine;

				int row = table.addRow();
				table.get(row, 0)
					.append("\t// Cache line ")
					.append(cacheLine);

				int offset = startByte % 64;
				if (offset != 0) {
					table.get(row, 1)
						.append("(offset ")
						.append(offset)
						.append(" bytes)");
				}
			}

			int row = addField(table, field);
			rows.put(field.getName(), row);
		}
		addPadding(table, layout.getByteSize() - lastByte);

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

		List<AccessPattern> structPatterns = patterns.getRankedPatterns(struct);
		SetMultimap<String, Integer> fieldPatterns = HashMultimap.create();
		SetMultimap<Integer, Integer> colPatterns = HashMultimap.create();
		int count = 0;
		long total = patterns.getCount(struct);
		final int MAX_COLS = 7;
		for (AccessPattern pattern : structPatterns) {
			int patternId = count++;

			int col = MAX_COLS;
			if (col >= table.nColumns()) {
				col = table.addColumn();
			}
			colPatterns.put(col, patternId);

			if (col < MAX_COLS) {
				int percentage = percent(patterns.getCount(pattern), total);
				table.get(0, col)
					.append(percentage)
					.append("%");
			} else {
				table.get(0, col)
					.replace(0, 3, "...");
			}

			for (var field : pattern.getFields()) {
				boolean read = pattern.reads(field);
				boolean written = pattern.writes(field);

				String name = field.getName();
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
					var origField = struct.getFields().get(fieldIds.get(field));
					var type = origField.getType().fullyUndecorate().resolve();
					if (patterns.getStructs().contains(type)) {
						var path = getResultPath(type);
						String href = path.getFileName().toString();
						typeCell.insert(1, "<a href='" + href + "'>")
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

		if (!layout.equals(struct.getLayout())) {
			out.println();
			out.print("<div class='comment' style='overflow-x: scroll;'>");
			out.println("/*");
			out.println();

			out.println("clang-reorder-fields command:");
			out.println();

			String fields = layout.getFields()
				.stream()
				.map(Field::getName)
				.collect(Collectors.joining(","));
			out.println("$ clang-reorder-fields \\");
			out.print("\t--record-name=");
			out.print(struct.getName());
			out.print(" \\\n\t--fields-order=");
			out.println(fields);

			out.println();
			out.println("Initializer macro:");
			out.println();

			String args = struct.getFields()
				.stream()
				.map(Field::getName)
				.collect(Collectors.joining(", "));
			String body = layout.getFields()
				.stream()
				.map(Field::getName)
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

	private int addField(Table table, Field field) {
		int row = table.addRow();
		StringBuilder spec = table.get(row, 0);
		StringBuilder decl = table.get(row, 1);
		field.getType().toC(field.getName(), spec, decl);
		spec.insert(0, "\t");
		decl.append(";");
		return row;
	}

	private void addPadding(Table table, int padding) {
		if (padding > 0) {
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
	private void renderAccessPatterns(BcpiStruct struct, AccessPatterns patterns, PrintWriter out) {
		out.println("<ul>");

		String decl = struct.toC();
		long total = patterns.getCount(struct);
		List<AccessPattern> structPatterns = patterns.getRankedPatterns(struct);
		int id = 0;
		for (AccessPattern pattern : structPatterns) {
			out.format("<li class='pattern pattern-%d' style='margin-top: 8px;'", id);
			out.format(" onmouseenter=\"highlight('.pattern-%d', false, true);\"", id);
			out.format(" onmouseleave=\"highlight('.pattern-%d', false, false);\"", id);
			out.format(" onclick=\"highlightSticky(this, '.pattern-%d');\">", id);

			long count = patterns.getCount(pattern);
			int percentage = percent(count, total);
			out.format("%d%% (%,d times)<br>\n", percentage, count);

			renderAccessPattern(pattern, decl, out);

			out.println("Occurs in");
			out.println("<ul class='functions'>");
			patterns.getFunctions(pattern)
				.stream()
				.map(f -> f.getName())
				.sorted()
				.map(f -> htmlEscape(f))
				.forEach(f -> out.format("<li><code>%s()</code>\n", f));
			out.println("</ul>");

			++id;
		}

		out.println("</ul>");
	}

	private void renderAccessPattern(AccessPattern pattern, String decl, PrintWriter out) {
		out.println("<code>" + htmlEscape(decl) + "</code>");
		out.println("<ul>");

		for (var field : pattern.getFields()) {
			out.print("<li>");

			String fieldDecl = field.getType().toC(field.getName());
			AccessPattern proj = pattern.project(field);
			if (proj == null) {
				String r = pattern.reads(field) ? "R" : "";
				String w = pattern.writes(field) ? "W" : "";
				out.format("<code>%s <strong>(%s%s)</strong></code>\n", htmlEscape(fieldDecl), r, w);
			} else {
				renderAccessPattern(proj, fieldDecl, out);
			}
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
