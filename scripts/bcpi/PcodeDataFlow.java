package bcpi;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Data Flow analysis on Ghidra pcode.
 */
class PcodeDataFlow {
	private final Map<Varnode, Facts> cache = new HashMap<>();

	/**
	 * Set the facts for a varnode.
	 */
	void setFacts(Varnode vn, Facts facts) {
		cache.put(vn, facts);
	}

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
		int opcode = -1;
		Varnode[] inputs = null;
		PcodeOp op = vn.getDef();
		if (op != null) {
			opcode = op.getOpcode();
			inputs = op.getInputs();
		}

		Facts facts = null;

		switch (opcode) {
			case PcodeOp.CAST:
			case PcodeOp.COPY:
				facts = getFacts(inputs[0]);
				break;

			case PcodeOp.MULTIEQUAL:
				// Phi node
				facts = Arrays.stream(inputs)
					.map(this::getFacts)
					.reduce(Facts::meet)
					.get();
				break;

			case PcodeOp.PTRADD:
				// This operator serves as a more compact representation of the pointer
				// calculation, input0 + input1 * input2, but also indicates explicitly that
				// input0 is a reference to an array data-type.
				facts = getFacts(inputs[0]).withArray(true);
				break;

			case PcodeOp.PTRSUB: {
				// A PTRSUB performs the simple pointer calculation, input0 + input1, but
				// also indicates explicitly that input0 is a reference to a structured
				// data-type and one of its subcomponents is being accessed.

				// input0: Varnode containing pointer to structure
				Varnode ptr = inputs[0];
				// input1: Varnode containing integer offset to a subcomponent
				Varnode offset = inputs[1];
				if (!offset.isConstant()) {
					break;
				}

				facts = getFacts(ptr).addOffset((int) offset.getOffset());
				break;
			}

			case PcodeOp.INT_ADD:
			case PcodeOp.INT_SUB: {
				// Not all pointer arithmetic becomes PTRSUB
				Varnode ptr = inputs[0];
				Varnode offset = inputs[1];

				Facts ptrFacts = getFacts(ptr);
				if (!ptrFacts.hasType()) {
					ptr = inputs[1];
					offset = inputs[0];
					ptrFacts = getFacts(ptr);
				}

				if (!ptrFacts.hasType() || !offset.isConstant()) {
					break;
				}

				int delta = (int) offset.getOffset();
				if (opcode == PcodeOp.INT_SUB) {
					delta = -delta;
				}
				facts = ptrFacts.addOffset(delta);
				break;
			}
		}

		Facts initial = Facts.initial(vn);
		if (facts == null) {
			facts = initial;
		}

		// If we lost precision tracking the original allocation type, recover
		// a lower bound from the varnode itself.
		if (!facts.hasType() && initial.hasType()) {
			facts = facts.withType(initial.getType());
		}

		return facts;
	}
}
