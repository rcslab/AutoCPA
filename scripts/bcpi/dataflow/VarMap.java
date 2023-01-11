package bcpi.dataflow;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * A function that maps varnodes to an abstract domain.
 */
@FunctionalInterface
public interface VarMap<T> {
	/**
	 * @return The value associated with the given varnode.
	 */
	T get(Varnode vn);

	/**
	 * @return A VarMap that applies an additional transformation.
	 */
	default <U> VarMap<U> andThen(Function<? super T, ? extends U> after) {
		return vn -> after.apply(get(vn));
	}

	/**
	 * @return The value associated with the given input.
	 */
	default T getInput(PcodeOp op, int input) {
		return get(op.getInput(input));
	}

	/**
	 * @return The values associated with each input.
	 */
	default List<T> getInputs(PcodeOp op) {
		return Arrays.stream(op.getInputs())
			.map(this::get)
			.collect(Collectors.toList());
	}
}
