package bcpi.dataflow;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.Arrays;
import java.util.BitSet;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.LongBinaryOperator;
import java.util.function.LongPredicate;
import java.util.function.LongUnaryOperator;
import java.util.function.UnaryOperator;

/**
 * The abstract domain for integer varnodes.
 */
public class IntDomain implements SparseDomain<IntDomain, IntDomain> {
	private static final BitSet SUPPORTED = new BitSet(PcodeOp.PCODE_MAX);
	static {
		SUPPORTED.set(PcodeOp.BOOL_AND);
		SUPPORTED.set(PcodeOp.BOOL_NEGATE);
		SUPPORTED.set(PcodeOp.BOOL_OR);
		SUPPORTED.set(PcodeOp.BOOL_XOR);
		SUPPORTED.set(PcodeOp.CAST);
		SUPPORTED.set(PcodeOp.COPY);
		SUPPORTED.set(PcodeOp.INT_2COMP);
		SUPPORTED.set(PcodeOp.INT_ADD);
		SUPPORTED.set(PcodeOp.INT_AND);
		SUPPORTED.set(PcodeOp.INT_DIV);
		SUPPORTED.set(PcodeOp.INT_EQUAL);
		SUPPORTED.set(PcodeOp.INT_LEFT);
		SUPPORTED.set(PcodeOp.INT_LESS);
		SUPPORTED.set(PcodeOp.INT_LESSEQUAL);
		SUPPORTED.set(PcodeOp.INT_MULT);
		SUPPORTED.set(PcodeOp.INT_NEGATE);
		SUPPORTED.set(PcodeOp.INT_NOTEQUAL);
		SUPPORTED.set(PcodeOp.INT_OR);
		SUPPORTED.set(PcodeOp.INT_REM);
		SUPPORTED.set(PcodeOp.INT_RIGHT);
		SUPPORTED.set(PcodeOp.INT_SDIV);
		SUPPORTED.set(PcodeOp.INT_SEXT);
		SUPPORTED.set(PcodeOp.INT_SLESS);
		SUPPORTED.set(PcodeOp.INT_SLESSEQUAL);
		SUPPORTED.set(PcodeOp.INT_SREM);
		SUPPORTED.set(PcodeOp.INT_SRIGHT);
		SUPPORTED.set(PcodeOp.INT_SUB);
		SUPPORTED.set(PcodeOp.INT_XOR);
		SUPPORTED.set(PcodeOp.INT_ZEXT);
		SUPPORTED.set(PcodeOp.MULTIEQUAL);
		SUPPORTED.set(PcodeOp.POPCOUNT);
		SUPPORTED.set(PcodeOp.SUBPIECE);
	}

	private final Flattice<Long> value;

	private IntDomain(Flattice<Long> value) {
		this.value = value;
	}

	/**
	 * @return The bottom element of this lattice.
	 */
	public static IntDomain bottom() {
		return new IntDomain(Flattice.bottom());
	}

	/**
	 * @return Whether this is the bottom lattice element.
	 */
	public boolean isBottom() {
		return this.value.isBottom();
	}

	/**
	 * @return The top element of this lattice.
	 */
	public static IntDomain top() {
		return new IntDomain(Flattice.top());
	}

	/**
	 * @return Whether this is the top lattice element.
	 */
	public boolean isTop() {
		return this.value.isTop();
	}

	/**
	 * @return An abstract value for a constant.
	 */
	public static IntDomain constant(long value) {
		return new IntDomain(Flattice.of(value));
	}

	/**
	 * @return Whether this abstract value is a constant.
	 */
	public boolean isConstant() {
		return this.value.isPresent();
	}

	/**
	 * @return The value of this integer, if it is constant.
	 */
	public OptionalLong getIfConstant() {
		return this.value
			.get()
			.map(OptionalLong::of)
			.orElseGet(OptionalLong::empty);
	}

	@Override
	public IntDomain copy() {
		return new IntDomain(this.value.copy());
	}

	@Override
	public boolean joinInPlace(IntDomain other) {
		return this.value.joinInPlace(other.value);
	}

	@Override
	public IntDomain getDefault(Varnode vn) {
		if (vn.isConstant()) {
			return constant(vn.getOffset());
		} else if (vn.getDef() == null) {
			// Parameters etc. can be anything
			return top();
		} else {
			// Locals start out uninitialized
			return bottom();
		}
	}

	/**
	 * @return Get this value as a constant, or throw.
	 */
	private long get() {
		return getIfConstant().getAsLong();
	}

	/** Apply a unary operator. */
	private IntDomain mapConstant(LongUnaryOperator func) {
		if (isBottom()) {
			return bottom();
		} else if (isConstant()) {
			try {
				return constant(func.applyAsLong(this.get()));
			} catch (ArithmeticException e) {
				// ...
			}
		}

		return top();
	}

	/** @return -this */
	public IntDomain negate() {
		return mapConstant(n -> -n);
	}

	/** @return ~this */
	public IntDomain not() {
		return mapConstant(n -> ~n);
	}

	/** @return The number of set bits. */
	public IntDomain bitCount() {
		return mapConstant(Long::bitCount);
	}

	/** Apply a binary operator. */
	private IntDomain mapConstants(IntDomain rhs, LongBinaryOperator func) {
		if (isBottom() || rhs.isBottom()) {
			return bottom();
		} else if (isConstant() && rhs.isConstant()) {
			try {
				return constant(func.applyAsLong(this.get(), rhs.get()));
			} catch (ArithmeticException e) {
				// ...
			}
		}

		return top();
	}

	/** @return this + rhs */
	public IntDomain add(IntDomain rhs) {
		return mapConstants(rhs, (l, r) -> l + r);
	}

	/** @return this - rhs */
	public IntDomain subtract(IntDomain rhs) {
		return mapConstants(rhs, (l, r) -> l - r);
	}

	/** @return this * rhs */
	public IntDomain multiply(IntDomain rhs) {
		return mapConstants(rhs, (l, r) -> l * r);
	}

	/** @return this / rhs */
	public IntDomain divide(IntDomain rhs) {
		return mapConstants(rhs, (l, r) -> l / r);
	}

	/** @return this % rhs */
	public IntDomain mod(IntDomain rhs) {
		return mapConstants(rhs, (l, r) -> l % r);
	}

	/** @return this / rhs */
	public IntDomain divideUnsigned(IntDomain rhs) {
		return mapConstants(rhs, Long::divideUnsigned);
	}

	/** @return this % rhs */
	public IntDomain modUnsigned(IntDomain rhs) {
		return mapConstants(rhs, Long::remainderUnsigned);
	}

	/** @return this & rhs */
	public IntDomain and(IntDomain rhs) {
		return mapConstants(rhs, (l, r) -> l & r);
	}

	/** @return this | rhs */
	public IntDomain or(IntDomain rhs) {
		return mapConstants(rhs, (l, r) -> l | r);
	}

	/** @return this ^ rhs */
	public IntDomain xor(IntDomain rhs) {
		return mapConstants(rhs, (l, r) -> l ^ r);
	}

	/** @return this << lhs */
	public IntDomain shiftLeft(IntDomain rhs) {
		return mapConstants(rhs, (l, r) -> l << r);
	}

	/** @return this >> lhs */
	public IntDomain shiftRight(IntDomain rhs) {
		return mapConstants(rhs, (l, r) -> l >> r);
	}

	/** @return this >>> lhs */
	public IntDomain shiftRightUnsigned(IntDomain rhs) {
		return mapConstants(rhs, (l, r) -> l >>> r);
	}

	/**
	 * @return A copy of this value truncated to fit the given varnode.
	 */
	private IntDomain truncate(Varnode vn) {
		long bits = 8 * vn.getSize();
		if (bits >= Long.SIZE) {
			return copy();
		}

		long mask = (1L << bits) - 1;
		return mapConstant(n -> n & mask);
	}

	/**
	 * @return A copy of this value sign-extended to fit the given varnode.
	 */
	private IntDomain signExtend(Varnode vn) {
		long bits = 8 * vn.getSize();
		if (bits >= Long.SIZE) {
			return copy();
		}

		long bit = 1L << bits;
		return mapConstant(n -> {
			if ((n & bit) == 0) {
				return n;
			} else {
				return n | -bit;
			}
		});
	}

	/**
	 * @return A VarMap that sign-extends.
	 */
	private static VarMap<IntDomain> sext(VarMap<IntDomain> map) {
		return v -> map.get(v).signExtend(v);
	}

	/**
	 * Evaluate a unary pcode operation.
	 */
	private static IntDomain unaryOp(PcodeOp op, VarMap<IntDomain> map, UnaryOperator<IntDomain> func) {
		var input = map.getInput(op, 0);
		return func.apply(input)
			.truncate(op.getOutput());
	}

	/**
	 * Evaluate a unary pcode predicate.
	 */
	private static IntDomain unaryPred(PcodeOp op, VarMap<IntDomain> map, LongPredicate pred) {
		return unaryOp(op, map, v -> v.mapConstant(n -> pred.test(n) ? 1 : 0));
	}

	/**
	 * Evaluate a binary pcode operation.
	 */
	private static IntDomain binaryOp(PcodeOp op, VarMap<IntDomain> map, BinaryOperator<IntDomain> func) {
		var lhs = map.getInput(op, 0);
		var rhs = map.getInput(op, 1);
		return func.apply(lhs, rhs)
			.truncate(op.getOutput());
	}

	@FunctionalInterface
	private interface LongBinaryPredicate {
		boolean test(long lhs, long rhs);
	}

	/**
	 * Evaluate a binary pcode predicate.
	 */
	private static IntDomain binaryPred(PcodeOp op, VarMap<IntDomain> map, LongBinaryPredicate pred) {
		return binaryOp(op, map, (a, b) -> a.mapConstants(b, (l, r) -> pred.test(l, r) ? 1 : 0));
	}

	@Override
	public boolean supports(PcodeOp op) {
		return SUPPORTED.get(op.getOpcode());
	}

	@Override
	public IntDomain visit(PcodeOp op, VarMap<IntDomain> map) {
		switch (op.getOpcode()) {
			case PcodeOp.COPY:
			case PcodeOp.CAST:
				return map.getInput(op, 0).copy();

			case PcodeOp.MULTIEQUAL:
				// Phi node
				return bottom().join(map.getInputs(op));

			case PcodeOp.SUBPIECE:
				// (l, r) -> l >> 8 * r
				return binaryOp(op, map, (l, r) -> l.shiftRightUnsigned(r.multiply(constant(8))));

			case PcodeOp.POPCOUNT:
				return unaryOp(op, map, IntDomain::bitCount);

			case PcodeOp.INT_EQUAL:
				return binaryPred(op, map, (l, r) -> l == r);
			case PcodeOp.INT_NOTEQUAL:
				return binaryPred(op, map, (l, r) -> l != r);

			case PcodeOp.INT_LESS:
				return binaryPred(op, map, (l, r) -> Long.compareUnsigned(l, r) < 0);
			case PcodeOp.INT_LESSEQUAL:
				return binaryPred(op, map, (l, r) -> Long.compareUnsigned(l, r) <= 0);

			case PcodeOp.INT_SLESS:
				return binaryPred(op, sext(map), (l, r) -> l < r);
			case PcodeOp.INT_SLESSEQUAL:
				return binaryPred(op, sext(map), (l, r) -> l <= r);

			case PcodeOp.INT_ZEXT:
				return map.getInput(op, 0).copy();
			case PcodeOp.INT_SEXT:
				return sext(map).getInput(op, 0).copy();

			case PcodeOp.INT_ADD:
				return binaryOp(op, map, IntDomain::add);
			case PcodeOp.INT_SUB:
				return binaryOp(op, map, IntDomain::subtract);

			case PcodeOp.INT_2COMP:
				return unaryOp(op, map, IntDomain::negate);
			case PcodeOp.INT_NEGATE:
				return unaryOp(op, map, IntDomain::not);

			case PcodeOp.INT_XOR:
				return binaryOp(op, map, IntDomain::xor);
			case PcodeOp.INT_AND:
				return binaryOp(op, map, IntDomain::and);
			case PcodeOp.INT_OR:
				return binaryOp(op, map, IntDomain::or);

			case PcodeOp.INT_LEFT:
				return binaryOp(op, map, IntDomain::shiftLeft);
			case PcodeOp.INT_RIGHT:
				return binaryOp(op, map, IntDomain::shiftRightUnsigned);
			case PcodeOp.INT_SRIGHT:
				return binaryOp(op, sext(map), IntDomain::shiftRight);

			case PcodeOp.INT_MULT:
				return binaryOp(op, map, IntDomain::multiply);

			case PcodeOp.INT_DIV:
				return binaryOp(op, map, IntDomain::divideUnsigned);
			case PcodeOp.INT_SDIV:
				return binaryOp(op, sext(map), IntDomain::divide);

			case PcodeOp.INT_REM:
				return binaryOp(op, map, IntDomain::modUnsigned);
			case PcodeOp.INT_SREM:
				return binaryOp(op, sext(map), IntDomain::mod);

			case PcodeOp.BOOL_NEGATE:
				return unaryPred(op, map, n -> n == 0);
			case PcodeOp.BOOL_XOR:
				return binaryPred(op, map, (l, r) -> (l ^ r) != 0);
			case PcodeOp.BOOL_AND:
				return binaryPred(op, map, (l, r) -> (l & r) != 0);
			case PcodeOp.BOOL_OR:
				return binaryPred(op, map, (l, r) -> (l | r) != 0);

			default:
				return top();
		}
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.value);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof IntDomain)) {
			return false;
		}

		var other = (IntDomain) obj;
		return this.value.equals(other.value);
	}

	@Override
	public String toString() {
		return this.value.toString();
	}
}
