package bcpi;

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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

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
	private final TaskMonitor monitor;
	private final GDirectedGraph<CodeBlockVertex, CodeBlockEdge> cfg;
	private final GDirectedGraph<CodeBlockVertex, CodeBlockEdge> reverseCfg;
	private final GDirectedGraph<CodeBlockVertex, GEdge<CodeBlockVertex>> domTree;
	private final GDirectedGraph<CodeBlockVertex, GEdge<CodeBlockVertex>> postDomTree;

	// Workaround for https://github.com/NationalSecurityAgency/ghidra/issues/2836
	private final Map<CodeBlockVertex, CodeBlockVertex> interner = new HashMap<>();

	public ControlFlowGraph(Function function, TaskMonitor monitor) throws Exception {
		this.bbModel = new BasicBlockModel(function.getProgram());
		this.monitor = monitor;
		this.cfg = new JungDirectedGraph<>();
		this.reverseCfg = new JungDirectedGraph<>();

		AddressSetView body = function.getBody();
		CodeBlockIterator blocks = bbModel.getCodeBlocksContaining(body, monitor);

		// Build the forward and backward CFGs for this function
		while (blocks.hasNext()) {
			CodeBlock block = blocks.next();
			CodeBlockVertex vertex = new CodeBlockVertex(block);

			CodeBlockReferenceIterator dests = block.getDestinations(monitor);
			while (dests.hasNext()) {
				CodeBlockReference dest = dests.next();
				CodeBlock destBlock = dest.getDestinationBlock();
				// Ignore non-local control flow
				if (body.contains(destBlock)) {
					addEdge(vertex, new CodeBlockVertex(destBlock));
				}
			}
		}

		// The function entry point is the source vertex
		CodeBlockVertex source = new CodeBlockVertex("SOURCE");
		for (CodeBlock block : bbModel.getCodeBlocksContaining(function.getEntryPoint(), monitor)) {
			addEdge(source, new CodeBlockVertex(block));
		}

		// Make sure the graph has a unique sink
		CodeBlockVertex sink = new CodeBlockVertex("SINK");
		Set<CodeBlockVertex> sinks = findSinksAndLoops();
		for (CodeBlockVertex vertex : sinks) {
			addEdge(vertex, sink);
		}

		this.domTree = GraphAlgorithms.findDominanceTree(this.cfg, monitor);
		this.postDomTree = GraphAlgorithms.findDominanceTree(this.reverseCfg, monitor);
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
	 * Infinite loops in the CFG do not reach the sink node, making us fail to construct the
	 * post-dominator tree.  This function finds the "last" node in every infinite loop so we
	 * can connect it to the sink.
	 */
	private Set<CodeBlockVertex> findSinksAndLoops() {
		Collection<CodeBlockVertex> sources = GraphAlgorithms.getSources(this.cfg);
		Set<CodeBlockVertex> seen = new HashSet<>(sources);
		Set<CodeBlockVertex> results = new HashSet<>();
		for (CodeBlockVertex source : sources) {
			findSinksAndLoops(source, new HashSet<>(), seen, results);
		}
		return results;
	}

	private void findSinksAndLoops(CodeBlockVertex vertex, Set<CodeBlockVertex> parents, Set<CodeBlockVertex> seen, Set<CodeBlockVertex> results) {
		boolean backOnly = true;
		parents.add(vertex);

		for (CodeBlockVertex child : this.cfg.getSuccessors(vertex)) {
			if (!parents.contains(child)) {
				backOnly = false;
				if (seen.add(child)) {
					findSinksAndLoops(child, parents, seen, results);
				}
			}
		}
		parents.remove(vertex);

		if (backOnly) {
			results.add(vertex);
		}
	}

	/**
	 * Get the basic blocks that are definitely reached after the given blocks.
	 */
	private Set<CodeBlockVertex> getDefiniteSuccessors(Collection<CodeBlockVertex> blocks) throws Exception {
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
	private Set<CodeBlockVertex> getDefinitePredecessors(List<CodeBlockVertex> blocks) throws Exception {
		return GraphAlgorithms.getAncestors(this.domTree, blocks);
	}

	/**
	 * Get the basic blocks that are likely executed when the given address reached.
	 */
	public Set<CodeBlock> getLikelyReachedBlocks(Address address) throws Exception {
		List<CodeBlockVertex> containing = new ArrayList<>();
		for (CodeBlock block : this.bbModel.getCodeBlocksContaining(address, this.monitor)) {
			containing.add(new CodeBlockVertex(block));
		}

		Set<CodeBlockVertex> vertices = new HashSet<>(containing);
		if (BcpiConfig.ANALYZE_FORWARD_FLOW) {
			vertices.addAll(getDefiniteSuccessors(containing));
		}
		if (BcpiConfig.ANALYZE_BACKWARD_FLOW) {
			vertices.addAll(getDefinitePredecessors(containing));
		}

		// TODO: Compute likely reached blocks as well

		return vertices.stream()
			.map(CodeBlockVertex::getCodeBlock)
			.filter(Objects::nonNull)
			.collect(Collectors.toSet());
	}
}
