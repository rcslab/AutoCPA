package bcpi;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Data Flow analysis on Ghidra pcode.
 */
class PcodeDataFlow {
	private final HashMap<Varnode, Facts> cache = new HashMap<>();

	/**
	 * Compute data flow facts for a varnode.
	 */
	Facts getFacts(Varnode vn) {
		Facts facts = cache.get(vn);
		if (facts != null) {
			return facts;
		}

		facts = new Facts();
		cache.put(vn, facts);

		// Fixpoint iteration
		Facts prev;
		do {
			prev = facts;
			facts = computeFacts(vn);
			cache.put(vn, facts);
		} while (!facts.equals(prev));

		return facts;
	}

	private Facts computeFacts(Varnode vn) {
		PcodeOp op = vn.getDef();
		if (op == null) {
			return new Facts();
		}

		Varnode[] inputs = op.getInputs();

		switch (op.getOpcode()) {
			case PcodeOp.CAST:
			case PcodeOp.COPY:
				return getFacts(inputs[0]);

			case PcodeOp.MULTIEQUAL:
				// Phi node
				return Arrays.stream(inputs)
					.map(this::getFacts)
					.reduce(Facts::meet)
					.get();

			case PcodeOp.PTRADD:
				// This operator serves as a more compact representation of the pointer
				// calculation, input0 + input1 * input2, but also indicates explicitly that
				// input0 is a reference to an array data-type.
				return getFacts(inputs[0]).withArray(true);

			case PcodeOp.PTRSUB: {
				// A PTRSUB performs the simple pointer calculation, input0 + input1, but
				// also indicates explicitly that input0 is a reference to a structured
				// data-type and one of its subcomponents is being accessed.

				// input0: Varnode containing pointer to structure
				Varnode base = inputs[0];
				// input1: Varnode containing integer offset to a subcomponent
				Varnode offset = inputs[1];
				if (!offset.isConstant()) {
					break;
				}

				DataType type = base.getHigh().getDataType();
				if (type instanceof TypeDef) {
					type = ((TypeDef) type).getBaseDataType();
				}
				if (type instanceof Pointer) {
					type = ((Pointer) type).getDataType();
				}
				if (type instanceof TypeDef) {
					type = ((TypeDef) type).getBaseDataType();
				}
				if (!(type instanceof Structure)) {
					break;
				}

				Structure struct = (Structure) type;
				int fieldOffset = (int) offset.getOffset();
				DataTypeComponent field = struct.getComponentAt(fieldOffset);
				return getFacts(base).withField(field);
			}
		}

		return new Facts();
	}
}
