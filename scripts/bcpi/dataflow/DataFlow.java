package bcpi.dataflow;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.SequenceNumber;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * The generic data flow analysis algorithm.
 */
public final class DataFlow<T extends Domain<T>> {
	private final T domain;
	private final ConcurrentMap<SequenceNumber, State> cache;

	/**
	 * An abstract state both before and after a program point.
	 */
	private class State {
		final T before = domain.copy();
		T after = null;

		/**
		 * Update this state from a change to one of its inputs.
		 *
		 * @return Whether this state changed.
		 */
		boolean update(T input) {
			if (this.before.joinInPlace(input)) {
				this.after = null;
				return true;
			} else {
				return false;
			}
		}

		/**
		 * Visit a program point, if necessary.
		 */
		T visit(PcodeOp op) {
			if (this.after == null) {
				this.after = this.before.visit(op);
			}
			return this.after;
		}
	}

	/**
	 * Create a new data flow context.
	 *
	 * @param domain
	 *            The initial value of the analysis domain.
	 */
	public DataFlow(T domain) {
		this.domain = domain;
		this.cache = new ConcurrentHashMap<>();
	}

	/**
	 * @return The solution to the data flow equations at the given program point.
	 */
	public T fixpoint(PcodeOp op) {
		// We use a work-list algorithm to iterate until fixpoint
		var workList = new ArrayDeque<PcodeOp>();

		// Dedup PcodeOps by SequenceNumber because PcodeOp doesn't override equals()
		var workSet = new HashSet<SequenceNumber>();

		// Keep track of each operation's outputs to propagate changes
		ListMultimap<SequenceNumber, PcodeOp> outputs = ArrayListMultimap.create();

		// Keep a separate local cache for thread safety
		var cache = new HashMap<SequenceNumber, State>();

		// Add the (transitive) inputs to the work list
		var inputs = new ArrayDeque<PcodeOp>();
		inputs.add(op);
		while (!inputs.isEmpty()) {
			var input = inputs.removeFirst();
			var iseq = input.getSeqnum();
			if (cache.containsKey(iseq)) {
				continue;
			}

			var state = this.cache.get(iseq);
			if (state == null) {
				state = new State();

				if (this.domain.supports(input)) {
					for (var child : this.domain.getInputs(input)) {
						inputs.addLast(child);
						outputs.put(child.getSeqnum(), input);
					}
				}
			}

			workList.addFirst(input);
			workSet.add(iseq);
			cache.put(iseq, state);
		}

		// Process the work list until it's empty
		while (!workList.isEmpty()) {
			var work = workList.removeFirst();
			var wseq = work.getSeqnum();
			workSet.remove(wseq);

			var state = cache.get(wseq);
			var after = state.visit(work);

			// Propagate changes to outputs
			for (var output : outputs.get(wseq)) {
				var oseq = output.getSeqnum();
				var ostate = cache.get(oseq);
				if (ostate.update(after)) {
					// Output changed, need to re-process it
					if (workSet.add(oseq)) {
						workList.addLast(output);
					}
				}
			}
		}

		// Save solutions for future calls
		this.cache.putAll(cache);

		return cache.get(op.getSeqnum()).after;
	}

	/**
	 * @return The solution to the data flow equations at a varnode's definition.
	 */
	public T fixpoint(Varnode vn) {
		var def = vn.getDef();
		if (def == null) {
			return this.domain.copy();
		} else {
			return fixpoint(def);
		}
	}
}
