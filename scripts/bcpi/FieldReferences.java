package bcpi;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
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

		// input1: Varnode containing pointer offset (to data|of destination)
		Varnode ptr = op.getInput(1);

		// LOAD:  output: Destination varnode.
		// STORE: input2: Varnode containing data to be stored.
		Varnode value = isRead ? op.getOutput() : op.getInput(2);

		Facts facts = dataFlow.getFacts(ptr);
		if (!facts.hasType() || !facts.hasOffset()) {
			return;
		}

		DataType type = facts.getType();
		int offset = facts.getOffset().getAsInt();
		int endOffset = offset + value.getSize();

		Set<FieldReference> fields = updateFields(op.getSeqnum().getTarget());
		DataTypes.getFieldsBetween(type, offset, endOffset)
			.stream()
			.map(f -> new FieldReference(f, facts.isArray(), isRead))
			.forEach(fields::add);
	}
}
