package bcpi;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
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
	private final BcpiDecompiler decomp;

	public FieldReferences(BcpiDecompiler decomp) {
		this.decomp = decomp;
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
	 * Collect the struct field references in the specified functions.
	 */
	public void collect(Collection<Function> functions) {
		Msg.info(this, String.format("Computing data flow for %,d functions", functions.size()));

		functions
			.parallelStream()
			.map(f -> this.decomp.getPcode(f))
			.filter(f -> f != null)
			.forEach(f -> computeDataFlow(f, new PcodeDataFlow()));
	}

	/**
	 * Compute data flow facts for a specific function.
	 */
	private void computeDataFlow(HighFunction highFunc, PcodeDataFlow dataFlow) {
		Iterable<PcodeOpAST> ops = () -> highFunc.getPcodeOps();
		for (PcodeOp op : ops) {
			processPcodeOp(dataFlow, op);
		}
	}

	/**
	 * Process a single pcode instruction.
	 */
	private void processPcodeOp(PcodeDataFlow dataFlow, PcodeOp op) {
		if (op.getOpcode() != PcodeOp.LOAD && op.getOpcode() != PcodeOp.STORE) {
			return;
		}
		boolean isRead = op.getOpcode() == PcodeOp.LOAD;

		Varnode[] inputs = op.getInputs();
		// input1: Varnode containing pointer offset (to data|of destination)
		Varnode ptr = inputs[1];

		Facts facts = dataFlow.getFacts(ptr);
		Field field = facts.getField();
		if (field == null) {
			return;
		}

		Set<FieldReference> fields = updateFields(op.getSeqnum().getTarget());
		fields.add(new FieldReference(field, facts.isArray(), isRead));
	}
}
