package bcpi;

import bcpi.util.BeamSearch;
import bcpi.util.BeamState;
import bcpi.util.Counter;

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
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

import com.google.common.base.Throwables;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A code block in a control flow graph.
 *
 * Not using ghidra.program.model.block.graph.CodeBlockVertex because it treats
 * all dummy vertices as equal, but we need two different dummy vertices.
 */
class CodeBlockVertex {
	private final CodeBlock block;
	private final String name;
	private final Object key;

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
public class ControlFlowGraph {
	private final BasicBlockModel bbModel;
	private final GDirectedGraph<CodeBlockVertex, CodeBlockEdge> cfg;
	private final GDirectedGraph<CodeBlockVertex, CodeBlockEdge> reverseCfg;
	private final GDirectedGraph<CodeBlockVertex, GEdge<CodeBlockVertex>> domTree;
	private final GDirectedGraph<CodeBlockVertex, GEdge<CodeBlockVertex>> postDomTree;
	private final Counter<CodeBlockVertex> coverage;
	private final Map<CodeBlockVertex, CodeBlockVertex> fallthroughEdges = new HashMap<>();

	// Workaround for https://github.com/NationalSecurityAgency/ghidra/issues/2836
	private final Map<CodeBlockVertex, CodeBlockVertex> interner = new HashMap<>();

	public ControlFlowGraph(Function function) {
		this.bbModel = new BasicBlockModel(function.getProgram());
		this.cfg = new JungDirectedGraph<>();
		this.reverseCfg = new JungDirectedGraph<>();
		this.coverage = new Counter<>();

		try {
			buildCfgs(function);
			this.domTree = GraphAlgorithms.findDominanceTree(this.cfg, TaskMonitor.DUMMY);
			this.postDomTree = GraphAlgorithms.findDominanceTree(this.reverseCfg, TaskMonitor.DUMMY);
		} catch (Exception e) {
			Throwables.throwIfUnchecked(e);
			throw new RuntimeException(e);
		}
	}

	private void buildCfgs(Function function) throws Exception {
		AddressSetView body = function.getBody();
		CodeBlockIterator blocks = bbModel.getCodeBlocksContaining(body, TaskMonitor.DUMMY);

		// Build the forward and backward CFGs for this function
		while (blocks.hasNext()) {
			CodeBlock block = blocks.next();
			CodeBlockVertex vertex = new CodeBlockVertex(block);

			CodeBlockReferenceIterator dests = block.getDestinations(TaskMonitor.DUMMY);
			while (dests.hasNext()) {
				CodeBlockReference dest = dests.next();
				CodeBlock destBlock = dest.getDestinationBlock();
				// Ignore non-local control flow
				if (body.contains(destBlock)) {
					CodeBlockVertex child = new CodeBlockVertex(destBlock);
					addEdge(vertex, child);
					if (dest.getFlowType().isFallthrough()) {
						this.fallthroughEdges.put(vertex, child);
					}
				}
			}
		}

		// Make sure the graph has a unique source
		CodeBlockVertex source = new CodeBlockVertex("SOURCE");
		for (CodeBlockVertex vertex : GraphAlgorithms.getEntryPoints(this.cfg)) {
			addEdge(source, vertex);
		}
		// The function entry point is always a source vertex
		for (CodeBlock block : bbModel.getCodeBlocksContaining(function.getEntryPoint(), TaskMonitor.DUMMY)) {
			addEdge(source, new CodeBlockVertex(block));
		}

		// Make sure the graph has a unique sink
		CodeBlockVertex sink = new CodeBlockVertex("SINK");
		for (CodeBlockVertex vertex : GraphAlgorithms.getEntryPoints(this.reverseCfg)) {
			addEdge(vertex, sink);
		}

		// Make sure empty CFGs are connected
		if (!this.cfg.containsVertex(source)) {
			addEdge(source, sink);
		}
	}

	/**
	 * Add coverage info for a code address.
	 */
	public void addCoverage(Address address, long count) {
		try {
			for (CodeBlock block : this.bbModel.getCodeBlocksContaining(address, TaskMonitor.DUMMY)) {
				this.coverage.add(new CodeBlockVertex(block), count);
			}
		} catch (Exception e) {
			Throwables.throwIfUnchecked(e);
			throw new RuntimeException(e);
		}
	}

	/**
	 * Add an edge to the forward and backward CFGs.
	 */
	private void addEdge(CodeBlockVertex from, CodeBlockVertex to) {
		from = interner.computeIfAbsent(from, v -> v);
		to = interner.computeIfAbsent(to, v -> v);

		this.cfg.addVertex(from);
		this.cfg.addVertex(to);
		this.cfg.addEdge(new CodeBlockEdge(from, to));

		this.reverseCfg.addVertex(to);
		this.reverseCfg.addVertex(from);
		this.reverseCfg.addEdge(new CodeBlockEdge(to, from));
	}

	/**
	 * Get the basic blocks that are definitely reached after the given blocks.
	 */
	private Set<CodeBlockVertex> getDefiniteSuccessors(Collection<CodeBlockVertex> blocks) {
		// We want all the nodes B such that all paths from A to END contain B, i.e.
		//
		//     {B | B postDom A}
		//
		// findPostDomainance(A) gets us {B | A postDom B} instead, so we have to compute it
		// by hand.  The post-dominance relation is just the dominance relation on the
		// transposed graph, so we use the dominance tree of the reversed CFG, and walk the
		// parents instead of the children.
		return GraphAlgorithms.getAncestors(this.postDomTree, blocks);
	}

	/**
	 * Get the basic blocks that are definitely reached before the given block.
	 */
	private Set<CodeBlockVertex> getDefinitePredecessors(List<CodeBlockVertex> blocks) {
		return GraphAlgorithms.getAncestors(this.domTree, blocks);
	}

	/**
	 * Get the basic blocks that are likely executed when the given address reached.
	 */
	public Set<CodeBlock> getLikelyReachedBlocks(Address address) {
		List<CodeBlockVertex> containing = new ArrayList<>();
		try {
			for (CodeBlock block : this.bbModel.getCodeBlocksContaining(address, TaskMonitor.DUMMY)) {
				containing.add(new CodeBlockVertex(block));
			}
		} catch (Exception e) {
			Throwables.throwIfUnchecked(e);
			throw new RuntimeException(e);
		}

		// Get definitely reached blocks
		Set<CodeBlockVertex> vertices = new HashSet<>(containing);
		if (BcpiConfig.ANALYZE_FORWARD_FLOW) {
			vertices.addAll(getDefiniteSuccessors(containing));
		}
		if (BcpiConfig.ANALYZE_BACKWARD_FLOW) {
			vertices.addAll(getDefinitePredecessors(containing));
		}

		// Get likely reached blocks
		if (BcpiConfig.BEAM_PATHS > 0 && BcpiConfig.BEAM_WIDTH > 0) {
			for (CodeBlockVertex vertex : containing) {
				if (BcpiConfig.ANALYZE_FORWARD_FLOW) {
					beamSearch(vertex, this.cfg, vertices);
				}
				if (BcpiConfig.ANALYZE_BACKWARD_FLOW) {
					beamSearch(vertex, this.reverseCfg, vertices);
				}
			}
		}

		return vertices.stream()
			.map(CodeBlockVertex::getCodeBlock)
			.filter(Objects::nonNull)
			.collect(Collectors.toSet());
	}

	/**
	 * Get the amount of coverage for a block.
	 */
	long getCoverage(CodeBlockVertex parent, CodeBlockVertex child) {
		long result = this.coverage.get(child);

		// Smooth out zero denominators
		++result;

		// Predict branches not taken in the absense of other information
		if (child.equals(this.fallthroughEdges.get(parent))) {
			++result;
		}

		return result;
	}

	/**
	 * Do beam search to find likely reached blocks based on coverage information.
	 */
	private void beamSearch(
		CodeBlockVertex start,
		GDirectedGraph<CodeBlockVertex, CodeBlockEdge> cfg,
		Set<CodeBlockVertex> vertices
	) {
		new BeamSearch<>(new BeamPath(this, cfg, start))
			.search(BcpiConfig.BEAM_WIDTH, BcpiConfig.BEAM_PATHS)
			.stream()
			.flatMap(BeamPath::vertices)
			.forEach(vertices::add);
	}
}

/**
 * A partial path found during beam search.
 */
class BeamPath implements BeamState<BeamPath> {
	/** The parent CFG. */
	final ControlFlowGraph cfg;
	/** The CFG itself. */
	final GDirectedGraph<CodeBlockVertex, CodeBlockEdge> graph;
	/** The previous node in the path. */
	final BeamPath prev;
	/** The current node in the path. */
	final CodeBlockVertex vertex;
	/** Log probability of this path. */
	final double weight;

	BeamPath(ControlFlowGraph cfg, GDirectedGraph<CodeBlockVertex, CodeBlockEdge> graph, CodeBlockVertex vertex) {
		this.cfg = cfg;
		this.graph = graph;
		this.prev = null;
		this.vertex = vertex;
		this.weight = 0.0;
	}

	BeamPath(BeamPath prev, CodeBlockVertex vertex, double weight) {
		this.cfg = prev.cfg;
		this.graph = prev.graph;
		this.prev = prev;
		this.vertex = vertex;
		this.weight = prev.weight + Math.log(weight);
	}

	Stream<CodeBlockVertex> vertices() {
		return Stream.iterate(this, p -> p.prev != null, p -> p.prev)
			.map(p -> p.vertex);
	}

	@Override
	public boolean isFinal() {
		return successors().isEmpty();
	}

	private long getCoverage(CodeBlockVertex dest) {
		return this.cfg.getCoverage(this.vertex, dest);
	}

	@Override
	public Collection<BeamPath> successors() {
		var successors = new HashSet<CodeBlockVertex>();
		var children = this.graph.getSuccessors(this.vertex);
		if (children != null) {
			successors.addAll(children);
		}

		var total = successors.stream()
			.mapToLong(this::getCoverage)
			.sum();

		// Don't add looping paths
		for (var tail = this; tail != null; tail = tail.prev) {
			successors.remove(tail.vertex);
		}

		return successors.stream()
			.map(v -> new BeamPath(this, v, (double)this.getCoverage(v) / total))
			.collect(Collectors.toList());
	}

	@Override
	public int compareTo(BeamPath other) {
		return Double.compare(this.weight, other.weight);
	}
}
