package bcpi;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.data.Composite;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Maps code addresses to the struct field(s) they reference.
 */
public class FieldReferences {
	private final ConcurrentMap<Address, Set<FieldReference>> refs = new ConcurrentHashMap<>();
	private final Linker linker;
	private final BcpiDecompiler decomp;
	private final BcpiControlFlow cfgs;

	public FieldReferences(Linker linker, BcpiDecompiler decomp, BcpiControlFlow cfgs) {
		this.linker = linker;
		this.decomp = decomp;
		this.cfgs = cfgs;
	}

	/**
	 * @return A new FieldReferences instance for nested function calls.
	 */
	private FieldReferences nested() {
		return new FieldReferences(this.linker, this.decomp, this.cfgs);
	}

	/**
	 * @return The fields accessed at a particular address.
	 */
	public Set<FieldReference> getFields(Address address) {
		return Optional.ofNullable(this.refs.get(address))
			.map(Collections::unmodifiableSet)
			.orElseGet(Collections::emptySet);
	}

	/**
	 * @return A mutable set of fields at the given address.
	 */
	private Set<FieldReference> updateFields(Address address) {
		return this.refs.computeIfAbsent(address, a -> ConcurrentHashMap.newKeySet());
	}

	/**
	 * Collect field references from a set of functions.
	 */
	public void collect(Collection<Function> functions) {
		Msg.info(this, String.format("Computing data flow for %,d functions", functions.size()));

		functions
			.parallelStream()
			.map(f -> this.decomp.getPcode(f))
			.filter(f -> f != null)
			.forEach(f -> computeDataFlow(BcpiConfig.IPA_DEPTH, f, new PcodeDataFlow()));
	}

	/**
	 * Compute data flow facts for a specific function.
	 */
	private void computeDataFlow(int depth, HighFunction highFunc, PcodeDataFlow dataFlow) {
		Iterable<PcodeOpAST> ops = () -> highFunc.getPcodeOps();
		for (PcodeOp op : ops) {
			processPcodeOp(depth, highFunc, dataFlow, op);
		}
	}

	/**
	 * Process a single pcode instruction.
	 */
	private void processPcodeOp(int depth, HighFunction highFunc, PcodeDataFlow dataFlow, PcodeOp op) {
		switch (op.getOpcode()) {
			case PcodeOp.CALL:
				processPcodeCall(depth, highFunc, dataFlow, op);
				break;
			case PcodeOp.LOAD:
			case PcodeOp.STORE:
				processPcodeLoadStore(dataFlow, op);
				break;
		}
	}

	/**
	 * Process a function call.
	 */
	private void processPcodeCall(int depth, HighFunction highFunc, PcodeDataFlow dataFlow, PcodeOp op) {
		if (depth == 0) {
			return;
		}

		// input0 (special): Location of next instruction to execute.
		Varnode[] inputs = op.getInputs();
		Varnode target = inputs[0];

		FunctionManager funcs = highFunc.getFunction().getProgram().getFunctionManager();
		Function targetFunc = Optional.ofNullable(funcs.getFunctionAt(target.getAddress()))
			.flatMap(this.linker::resolve)
			.orElse(null);
		if (targetFunc == null) {
			return;
		}

		HighFunction highTarget = this.decomp.getPcode(targetFunc);
		if (highTarget == null) {
			return;
		}

		LocalSymbolMap locals = highTarget.getLocalSymbolMap();
		PcodeDataFlow nestedFlow = new PcodeDataFlow();
		for (int i = 0; i < locals.getNumParams() && i + 1 < inputs.length; ++i) {
			HighParam param = locals.getParam(i);
			if (param == null) {
				continue;
			}
			for (Varnode vn : param.getInstances()) {
				// Copy facts from the call arguments to the formal parameters
				Facts facts = dataFlow.getFacts(inputs[i + 1]);
				nestedFlow.setFacts(vn, facts);
			}
		}

		FieldReferences nestedRefs = nested();
		nestedRefs.computeDataFlow(depth - 1, highTarget, nestedFlow);

		// Reassign field references from reached callee addresses to the caller
		Set<FieldReference> callFields = updateFields(op.getSeqnum().getTarget());
		ControlFlowGraph cfg = this.cfgs.getCfg(targetFunc);
		for (CodeBlock block : cfg.getLikelyReachedBlocks(targetFunc.getEntryPoint())) {
			for (Address nestedAddr : block.getAddresses(true)) {
				callFields.addAll(nestedRefs.getFields(nestedAddr));
			}
		}
	}

	/**
	 * Process a memory load/store instruction.
	 */
	private void processPcodeLoadStore(PcodeDataFlow dataFlow, PcodeOp op) {
		boolean isRead = op.getOpcode() == PcodeOp.LOAD;

		// input1: Varnode containing pointer offset (to data|of destination)
		Varnode ptr = op.getInput(1);

		// LOAD:  output: Destination varnode.
		// STORE: input2: Varnode containing data to be stored.
		Varnode value = isRead ? op.getOutput() : op.getInput(2);

		Facts facts = dataFlow.getFacts(ptr);
		if (!facts.hasType() || !facts.hasOffset()) {
			return;
		}

		Composite type = facts.getType();
		int offset = facts.getOffset().getAsInt();
		int size = value.getSize();

		if (offset < 0 || offset + size > type.getLength()) {
			return;
		}

		updateFields(op.getSeqnum().getTarget())
			.add(new FieldReference(type, facts.isArray(), offset, size, isRead));
	}
}
