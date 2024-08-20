package bcpi.dataflow;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import com.google.common.math.LongMath;
import com.google.common.primitives.UnsignedLong;

import java.util.BitSet;
import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.function.BinaryOperator;
import java.util.function.LongBinaryOperator;
import java.util.function.LongFunction;
import java.util.function.LongPredicate;
import java.util.function.LongUnaryOperator;
import java.util.function.UnaryOperator;

/**
 * The abstract domain for integer varnodes.
 */
public class IntDomain implements Lattice<IntDomain> {
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

	// Represents a congruence class of numbers
	//
	//     {o + k*m | k ∈ ℤ}
	//
	// Constants are represented by m == 0; otherwise, we have an infinite
	// set of integers satisfying
	//
	//     {n | n == o (mod m)}
	//
	// The top lattice element is ℤ itself, encoded as o == 0, m == 1.
	// The bottom lattice element is the empty set, encoded as o == 1, m == 1.
	private long offset;
	private long modulus;

	private IntDomain(long offset, long modulus) {
		this.offset = offset;
		this.modulus = modulus;
	}

	/**
	 * Calculate the greatest common divisor.
	 */
	private static long gcd(long x, long y) {
		return LongMath.gcd(Math.absExact(x), Math.absExact(y));
	}

	/**
	 * 3-argument gcd.
	 */
	private static long gcd(long x, long y, long z) {
		return gcd(gcd(x, y), z);
	}

	/**
	 * Reduce modulo a possibly-zero modulus.
	 */
	private static long reduce(long offset, long modulus) {
		if (modulus == 0) {
			return offset;
		} else {
			return Math.floorMod(offset, modulus);
		}
	}

	/**
	 * Create a new IntDomain, automatically reducing the offset.
	 */
	private static IntDomain create(long offset, long modulus) {
		try {
			modulus = Math.absExact(modulus);
			offset = reduce(offset, modulus);
			return new IntDomain(offset, modulus);
		} catch (ArithmeticException e) {
			return top();
		}
	}

	/**
	 * @return The bottom element of this lattice.
	 */
	public static IntDomain bottom() {
		return new IntDomain(1, 1);
	}

	/**
	 * @return Whether this is the bottom lattice element.
	 */
	public boolean isBottom() {
		return this.offset == 1 && this.modulus == 1;
	}

	/**
	 * @return The top element of this lattice.
	 */
	public static IntDomain top() {
		return new IntDomain(0, 1);
	}

	/**
	 * @return Whether this is the top lattice element.
	 */
	public boolean isTop() {
		return this.offset == 0 && this.modulus == 1;
	}

	/**
	 * @return An abstract value for a constant.
	 */
	public static IntDomain constant(long value) {
		return new IntDomain(value, 0);
	}

	/**
	 * @return Whether this abstract value is a constant.
	 */
	public boolean isConstant() {
		return this.modulus == 0;
	}

	/**
	 * @return The value of this integer, if it is constant.
	 */
	public OptionalLong getIfConstant() {
		if (isConstant()) {
			return OptionalLong.of(this.offset);
		} else {
			return OptionalLong.empty();
		}
	}

	/**
	 * @return An abstract value for an arbitrary multiple.
	 */
	public static IntDomain multipleOf(long modulus) {
		return create(0, modulus);
	}

	/**
	 * @return Whether this value could equal the given number.
	 */
	public boolean contains(long value) {
		return reduce(value, this.modulus) == this.offset;
	}

	@Override
	public IntDomain copy() {
		return new IntDomain(this.offset, this.modulus);
	}

	@Override
	public boolean joinInPlace(IntDomain other) {
		var joined = join(other);
		var same = equals(joined);
		this.modulus = joined.modulus;
		this.offset = joined.offset;
		return !same;
	}

	@Override
	public IntDomain join(IntDomain other) {
		if (isBottom()) {
			return other.copy();
		} else if (other.isBottom()) {
			return copy();
		}

		return map(other, (a, m, b, n) -> {
			var diff = Math.subtractExact(Math.max(a, b), Math.min(a, b));
			var gcd = gcd(m, n, diff);
			return create(a, gcd);
		});
	}

	public static IntDomain initial(VarOp vop) {
		var vn = vop.getVar();
		if (vn.isConstant()) {
			return constant(vn.getOffset());
		} else if (vop.getOp() == null) {
			// Parameters etc. can be anything
			return top();
		} else {
			// Locals start out uninitialized
			return bottom();
		}
	}

	@FunctionalInterface
	private interface UnaryOp {
		IntDomain apply(long offset, long modulus);
	}

	/** Compute a new value from this offset and modulus, propagating bottom. */
	private IntDomain map(UnaryOp op) {
		if (isBottom()) {
			return bottom();
		}

		try {
			return op.apply(this.offset, this.modulus);
		} catch (ArithmeticException e) {
			// ...
		}

		return top();
	}

	@FunctionalInterface
	private interface UnaryConstOp {
		IntDomain apply(long n);
	}

	/** Apply a unary operator if the input is constant. */
	private IntDomain mapConstant(UnaryConstOp op) {
		return map((o, m) -> m == 0 ? op.apply(o) : top());
	}

	/** Apply a unary operator if the input is constant. */
	private IntDomain mapLong(LongUnaryOperator op) {
		return mapConstant(n -> constant(op.applyAsLong(n)));
	}

	/** @return -this */
	public IntDomain negate() {
		return map((o, m) -> create(-o, m));
	}

	/** @return ~this */
	public IntDomain not() {
		return this.add(constant(1)).negate();
	}

	/** @return The number of set bits. */
	public IntDomain bitCount() {
		return mapLong(Long::bitCount);
	}

	@FunctionalInterface
	private interface BinaryOp {
		IntDomain apply(long a, long m, long b, long n);
	}

	/** Compute a new value from two offsets and moduli, propagating bottom. */
	private IntDomain map(IntDomain other, BinaryOp op) {
		return map((a, m) -> other.map((b, n) -> op.apply(a, m, b, n)));
	}

	/** @return this + rhs */
	public IntDomain add(IntDomain rhs) {
		return map(rhs, (a, m, b, n) -> {
			var offset = Math.addExact(a, b);
			var gcd = gcd(m, n);
			return create(offset, gcd);
		});
	}

	/** @return this + rhs */
	public IntDomain add(long rhs) {
		return add(constant(rhs));
	}

	/** @return this - rhs */
	public IntDomain subtract(IntDomain rhs) {
		return map(rhs, (a, m, b, n) -> {
			var offset = Math.subtractExact(a, b);
			var gcd = gcd(m, n);
			return create(offset, gcd);
		});
	}

	/** @return this - rhs */
	public IntDomain subtract(long rhs) {
		return subtract(constant(rhs));
	}

	/** @return this * rhs */
	public IntDomain multiply(IntDomain rhs) {
		return map(rhs, (a, m, b, n) -> {
			// See https://math.stackexchange.com/q/4679238/152767
			var ab = Math.multiplyExact(a, b);
			var an = Math.multiplyExact(a, n);
			var bm = Math.multiplyExact(b, m);
			var mn = Math.multiplyExact(m, n);
			return create(ab, gcd(gcd(an, bm), mn));
		});
	}

	/** @return this * rhs */
	public IntDomain multiply(long rhs) {
		return multiply(constant(rhs));
	}

	/** @return this / rhs */
	public IntDomain divide(IntDomain rhs) {
		return rhs.mapConstant(r -> {
			if (r == 0) {
				return bottom();
			}

			return map((o, m) -> {
				if (m % r != 0) {
					return top();
				}

				// Negative dividends give a different quotient
				var pos = create(o / r, m / r);
				var neg = create((o - m) / r, m / r);
				return pos.join(neg);
			});
		});
	}

	/** @return this / rhs */
	public IntDomain divide(long rhs) {
		return divide(constant(rhs));
	}

	/** @return this % rhs */
	public IntDomain remainder(IntDomain rhs) {
		return rhs.mapConstant(r -> {
			if (r == 0) {
				return bottom();
			}

			return map((o, m) -> {
				long modulus;
				if (m % r == 0) {
					modulus = 0;
				} else {
					modulus = gcd(m, r);
				}
				// Negative dividends give a different remainder
				var pos = create(o % r, modulus);
				var neg = create((o - m) % r, modulus);
				return pos.join(neg);
			});
		});
	}

	/** @return this % rhs */
	public IntDomain remainder(long rhs) {
		return remainder(constant(rhs));
	}

	/** @return |this| % rhs */
	public IntDomain mod(IntDomain rhs) {
		return rhs.mapConstant(r -> {
			if (r == 0) {
				return bottom();
			}

			return map((o, m) -> {
				long modulus;
				if (m % r == 0) {
					modulus = 0;
				} else {
					modulus = gcd(m, r);
				}
				return create(o % r, modulus);
			});
		});
	}

	/** @return |this| % rhs */
	public IntDomain mod(long rhs) {
		return mod(constant(rhs));
	}

	/** @return this / rhs */
	public IntDomain divideUnsigned(IntDomain rhs) {
		return rhs.mapConstant(r -> {
			if (r == 0) {
				return bottom();
			}

			return map((o, m) -> {
				if (Long.remainderUnsigned(m, r) != 0) {
					return top();
				}

				var offset = Long.divideUnsigned(o, r);
				var modulus = Long.divideUnsigned(m, r);
				return create(offset, modulus);
			});
		});
	}

	/** @return this / rhs */
	public IntDomain divideUnsigned(long rhs) {
		return divideUnsigned(constant(rhs));
	}

	/** @return this % rhs */
	public IntDomain remainderUnsigned(IntDomain rhs) {
		return rhs.mapConstant(r -> {
			if (r == 0) {
				return bottom();
			}

			return map((o, m) -> {
				long modulus;
				if (Long.remainderUnsigned(m, r) == 0) {
					modulus = 0;
				} else {
					var um = UnsignedLong.fromLongBits(m).bigIntegerValue();
					var ur = UnsignedLong.fromLongBits(r).bigIntegerValue();
					modulus = um.gcd(ur).longValueExact();
				}
				return create(Long.remainderUnsigned(o, r), modulus);
			});
		});
	}

	/** @return this % rhs */
	public IntDomain remainderUnsigned(long rhs) {
		return remainderUnsigned(constant(rhs));
	}

	@FunctionalInterface
	private interface BinaryConstOp {
		IntDomain apply(long lhs, long rhs);
	}

	/** Apply a binary operator if the inputs are both constant. */
	private IntDomain mapConstants(IntDomain rhs, BinaryConstOp op) {
		return mapConstant(l -> rhs.mapConstant(r -> op.apply(l, r)));
	}

	/** Apply a binary operator if the inputs are both constant. */
	private IntDomain mapLongs(IntDomain rhs, LongBinaryOperator op) {
		return mapConstants(rhs, (l, r) -> constant(op.applyAsLong(l, r)));
	}

	/** @return this & rhs */
	public IntDomain and(IntDomain rhs) {
		return rhs.mapConstant(r -> {
			if ((r & (r + 1)) == 0) {
				// l & 0xFF == l % 0x100
				return mod(rhs.add(constant(1)));
			} else {
				return mapLong(l -> l & r);
			}
		});
	}

	/** @return this & rhs */
	public IntDomain and(long rhs) {
		return and(constant(rhs));
	}

	/** @return this | rhs */
	public IntDomain or(IntDomain rhs) {
		return mapLongs(rhs, (l, r) -> l | r);
	}

	/** @return this | rhs */
	public IntDomain or(long rhs) {
		return or(constant(rhs));
	}

	/** @return this ^ rhs */
	public IntDomain xor(IntDomain rhs) {
		return mapLongs(rhs, (l, r) -> l ^ r);
	}

	/** @return this ^ rhs */
	public IntDomain xor(long rhs) {
		return xor(constant(rhs));
	}

	/** @return this << rhs */
	public IntDomain shiftLeft(IntDomain rhs) {
		return rhs.mapConstant(r -> {
			if (r >= 0 && r < Long.SIZE) {
				return this.multiply(1L << r);
			} else {
				return constant(0);
			}
		});
	}

	/** @return this << rhs */
	public IntDomain shiftLeft(long rhs) {
		return shiftLeft(constant(rhs));
	}

	/** @return this >> rhs */
	public IntDomain shiftRight(IntDomain rhs) {
		return mapLongs(rhs, (l, r) -> {
			if (r >= 0 && r < Long.SIZE) {
				return l >> r;
			} else {
				return 0;
			}
		});
	}

	/** @return this >> rhs */
	public IntDomain shiftRight(long rhs) {
		return shiftRight(constant(rhs));
	}

	/** @return this >>> rhs */
	public IntDomain shiftRightUnsigned(IntDomain rhs) {
		return mapLongs(rhs, (l, r) -> {
			if (r >= 0 && r < Long.SIZE) {
				return l >>> r;
			} else {
				return 0;
			}
		});
	}

	/** @return this >>> rhs */
	public IntDomain shiftRightUnsigned(long rhs) {
		return shiftRightUnsigned(constant(rhs));
	}

	/**
	 * @return A copy of this value truncated to fit the given varnode.
	 */
	private IntDomain truncate(Varnode vn) {
		long bits = 8 * vn.getSize();
		if (bits < Long.SIZE && isConstant()) {
			return mod(1L << bits);
		} else {
			return copy();
		}
	}

	/**
	 * @return A copy of this value sign-extended to fit the given varnode.
	 */
	private IntDomain signExtend(Varnode vn) {
		long bits = 8 * vn.getSize();
		if (bits < Long.SIZE && isConstant()) {
			long bit = 1L << bits;
			return mapConstant(n -> constant((n & bit) == 0 ? n : n | -bit));
		} else {
			return copy();
		}
	}

	private static IntDomain getInput(List<BcpiDomain> inputs, int i) {
		return inputs.get(i).getIntFacts();
	}

	/**
	 * Evaluate a unary pcode operation.
	 */
	private static IntDomain unaryOp(PcodeOp op, List<BcpiDomain> inputs, UnaryOperator<IntDomain> func) {
		var input = getInput(inputs, 0);
		return func.apply(input)
			.truncate(op.getOutput());
	}

	/** @return this != 0 */
	private IntDomain isNonzero() {
		var canBeZero = contains(0);
		var canBeNonzero = !isBottom() && (this.offset != 0 || this.modulus != 0);
		if (canBeZero && canBeNonzero) {
			return top();
		} else if (canBeZero) {
			return constant(0);
		} else if (canBeNonzero) {
			return constant(1);
		} else {
			return bottom();
		}
	}

	/** @return this == 0 */
	private IntDomain isZero() {
		return constant(1).subtract(isNonzero());
	}

	/**
	 * Evaluate a binary pcode operation.
	 */
	private static IntDomain binaryOp(PcodeOp op, List<BcpiDomain> inputs, BinaryOperator<IntDomain> func) {
		var lhs = getInput(inputs, 0);
		var rhs = getInput(inputs, 1);
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
	private static IntDomain binaryPred(PcodeOp op, List<BcpiDomain> inputs, LongBinaryPredicate pred) {
		return binaryOp(op, inputs, (a, b) -> a.mapConstants(b, (l, r) -> constant(pred.test(l, r) ? 1 : 0)));
	}

	public boolean supports(VarOp vop) {
		var op = vop.getOp();
		if (op == null) {
			return false;
		}

		return SUPPORTED.get(op.getOpcode());
	}

	public IntDomain visit(PcodeOp op, List<BcpiDomain> inputs) {
		switch (op.getOpcode()) {
			case PcodeOp.COPY:
			case PcodeOp.CAST:
				return getInput(inputs, 0).copy();

			case PcodeOp.MULTIEQUAL: {
				// Phi node
				var ret = bottom();
				for (var input : inputs) {
					ret.joinInPlace(input.getIntFacts());
				}
				return ret;
			}

			case PcodeOp.SUBPIECE:
				// (l, r) -> l >> 8 * r
				return binaryOp(op, inputs, (l, r) -> l.shiftRightUnsigned(r.multiply(8)));

			case PcodeOp.POPCOUNT:
				return unaryOp(op, inputs, IntDomain::bitCount);

			case PcodeOp.INT_EQUAL:
				// l == r <=> (l - r) != 0
				return binaryOp(op, inputs, IntDomain::subtract).isNonzero();
			case PcodeOp.INT_NOTEQUAL:
				// l == r <=> (l - r) == 0
				return binaryOp(op, inputs, IntDomain::subtract).isZero();

			case PcodeOp.INT_LESS:
				return binaryPred(op, inputs, (l, r) -> Long.compareUnsigned(l, r) < 0);
			case PcodeOp.INT_LESSEQUAL:
				return binaryPred(op, inputs, (l, r) -> Long.compareUnsigned(l, r) <= 0);

			case PcodeOp.INT_SLESS:
				return binaryPred(op, inputs, (l, r) -> l < r);
			case PcodeOp.INT_SLESSEQUAL:
				return binaryPred(op, inputs, (l, r) -> l <= r);

			case PcodeOp.INT_ZEXT:
				return getInput(inputs, 0).copy();
			case PcodeOp.INT_SEXT:
				return getInput(inputs, 0)
					.signExtend(op.getOutput());

			case PcodeOp.INT_ADD:
				return binaryOp(op, inputs, IntDomain::add);
			case PcodeOp.INT_SUB:
				return binaryOp(op, inputs, IntDomain::subtract);

			case PcodeOp.INT_2COMP:
				return unaryOp(op, inputs, IntDomain::negate);
			case PcodeOp.INT_NEGATE:
				return unaryOp(op, inputs, IntDomain::not);

			case PcodeOp.INT_XOR:
				return binaryOp(op, inputs, IntDomain::xor);
			case PcodeOp.INT_AND:
				return binaryOp(op, inputs, IntDomain::and);
			case PcodeOp.INT_OR:
				return binaryOp(op, inputs, IntDomain::or);

			case PcodeOp.INT_LEFT:
				return binaryOp(op, inputs, IntDomain::shiftLeft);
			case PcodeOp.INT_RIGHT:
				return binaryOp(op, inputs, IntDomain::shiftRightUnsigned);
			case PcodeOp.INT_SRIGHT:
				return binaryOp(op, inputs, IntDomain::shiftRight);

			case PcodeOp.INT_MULT:
				return binaryOp(op, inputs, IntDomain::multiply);

			case PcodeOp.INT_DIV:
				return binaryOp(op, inputs, IntDomain::divideUnsigned);
			case PcodeOp.INT_SDIV:
				return binaryOp(op, inputs, IntDomain::divide);

			case PcodeOp.INT_REM:
				return binaryOp(op, inputs, IntDomain::remainderUnsigned);
			case PcodeOp.INT_SREM:
				return binaryOp(op, inputs, IntDomain::remainder);

			case PcodeOp.BOOL_NEGATE:
				return getInput(inputs, 0).isZero();
			case PcodeOp.BOOL_XOR:
				return binaryOp(op, inputs, IntDomain::xor).isNonzero();
			case PcodeOp.BOOL_AND:
				return binaryOp(op, inputs, IntDomain::and).isNonzero();
			case PcodeOp.BOOL_OR:
				return binaryOp(op, inputs, IntDomain::or).isNonzero();

			default:
				return top();
		}
	}

	@Override
	public int hashCode() {
		var x = this.modulus;
		var y = this.offset;
		return Long.hashCode((x + y) * (x + y + 1) / 2 + y);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof IntDomain)) {
			return false;
		}

		var other = (IntDomain) obj;
		return this.modulus == other.modulus
			&& this.offset == other.offset;
	}

	@Override
	public String toString() {
		if (isBottom()) {
			return "⊥";
		} else if (isTop()) {
			return "⊤";
		} else if (isConstant()) {
			return String.format("{%d}", this.offset);
		} else {
			return String.format("{%d (mod %d)}", this.offset, this.modulus);
		}
	}

	private static final boolean CHECK = IntDomain.class.desiredAssertionStatus();
	private static final long CHECK_MIN = -16;
	private static final long CHECK_MAX = 16;

	/**
	 * Check that the IntDomain implementation of a unary operator is
	 * consistent with the same operation on longs.
	 */
	private static void checkUnary(LongUnaryOperator f, UnaryOperator<IntDomain> g) {
		// Check f(x) == g(x) for many x
		for (long x = CHECK_MIN; x <= CHECK_MAX; ++x) {
			var ix = constant(x);
			var fx = f.applyAsLong(x);
			var gx = g.apply(constant(x));
			assert gx.equals(constant(fx));

			// Check f(x) ∈ g(x ⊔ y) for many y
			for (long y = CHECK_MIN; y <= CHECK_MAX; ++y) {
				var xy = ix.join(constant(y));
				var gxy = g.apply(xy);
				assert gxy.contains(fx);
			}
		}
	}

	/**
	 * Check that the IntDomain implementation of a binary operator is
	 * consistent with the same operation on longs.
	 */
	private static void checkBinary(LongPredicate rhsRange, LongPredicate joinRange, LongBinaryOperator f, BinaryOperator<IntDomain> g) {
		// Check f(x, y) == g(x, y) for many x, y
		for (long x = CHECK_MIN; x <= CHECK_MAX; ++x) {
			var ix = constant(x);

			for (long y = CHECK_MIN; y <= CHECK_MAX; ++y) {
				if (!rhsRange.test(y)) {
					continue;
				}

				var iy = constant(y);
				var fxy = f.applyAsLong(x, y);
				var gxy = g.apply(ix, iy);
				assert gxy.equals(constant(fxy));

				if (!joinRange.test(x) || !joinRange.test(y)) {
					continue;
				}

				// Check f(x, y) ∈ g(x ⊔ z, y ⊔ w) for many z, w
				for (long z = CHECK_MIN; z <= CHECK_MAX; ++z) {
					if (!joinRange.test(z)) {
						continue;
					}

					var xz = ix.join(constant(z));

					for (long w = CHECK_MIN; w <= CHECK_MAX; ++w) {
						if (!rhsRange.test(w) || !joinRange.test(w)) {
							continue;
						}

						var yw = iy.join(constant(w));
						var gxzyw = g.apply(xz, yw);
						assert gxzyw.contains(fxy);
					}
				}
			}
		}
	}

	private static void checkBinary(LongPredicate rhsRange, LongBinaryOperator f, BinaryOperator<IntDomain> g) {
		checkBinary(rhsRange, n -> true, f, g);
	}

	private static void checkBinary(LongBinaryOperator f, BinaryOperator<IntDomain> g) {
		checkBinary(y -> true, f, g);
	}

	static {
		if (CHECK) {
			// Correctness checks
			checkUnary(x -> -x, IntDomain::negate);
			checkUnary(x -> ~x, IntDomain::not);
			checkUnary(Long::bitCount, IntDomain::bitCount);

			checkBinary((x, y) -> x + y, IntDomain::add);
			checkBinary((x, y) -> x - y, IntDomain::subtract);
			checkBinary((x, y) -> x * y, IntDomain::multiply);

			checkBinary(y -> y != 0, (x, y) -> x / y, IntDomain::divide);
			checkBinary(y -> y != 0, (x, y) -> x % y, IntDomain::remainder);

			checkBinary(y -> y != 0, n -> n >= 0, Long::divideUnsigned, IntDomain::divideUnsigned);
			checkBinary(y -> y != 0, n -> n >= 0, Long::remainderUnsigned, IntDomain::remainderUnsigned);

			checkBinary(y -> y >= 0, (x, y) -> x << y, IntDomain::shiftLeft);
			checkBinary(y -> y >= 0, (x, y) -> x >> y, IntDomain::shiftRight);
			checkBinary(y -> y >= 0, (x, y) -> x >>> y, IntDomain::shiftRightUnsigned);

			// QOI checks
			var max = constant(Long.MAX_VALUE);
			assert max.add(max).equals(top());

			assert top().multiply(3).equals(multipleOf(3));

			assert multipleOf(8).divide(2).equals(multipleOf(4));
			assert create(2, 8).divide(2).equals(create(1, 4));
			assert create(5, 8).divideUnsigned(2).equals(create(2, 4));
			assert constant(1).divide(0).equals(bottom());

			assert create(1, 3).mod(3).equals(constant(1));
			assert create(1, 9).mod(3).equals(constant(1));
			assert create(1, 3).mod(9).equals(create(1, 3));
			assert create(1, 3).mod(4).equals(top());
			assert constant(1).mod(0).equals(bottom());

			assert create(1, 16).and(0xF).equals(constant(1));
		}
	}
}
