package bcpi.dataflow;

import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.PcodeOp;

import java.util.Objects;

/**
 * A domain that maps varnodes to abstract values.
 */
public final class VarDomain<T extends SparseDomain<T, T>> extends ForwardDomain<VarDomain<T>> {
	private final T domain;
	private final MapLattice<Varnode, T> map;

	private VarDomain(T domain, MapLattice<Varnode, T> map) {
		this.domain = domain;
		this.map = map;
	}

	/**
	 * @return The bottom lattice element.
	 */
	public static <U extends SparseDomain<U, U>> VarDomain<U> bottom(U domain) {
		return new VarDomain<U>(domain, MapLattice.bottom());
	}

	/**
	 * @return Whether this is the bottom lattice element.
	 */
	public boolean isBottom() {
		return this.map.isBottom();
	}

	/**
	 * @return The value associated with the given varnode.
	 */
	public T get(Varnode vn) {
		return this.map.getOrElse(vn, this.domain::getDefault);
	}

	/**
	 * Override the value for the given varnode.
	 *
	 * @return Whether the mapping changed.
	 */
	public boolean put(Varnode vn, T value) {
		return this.map.put(vn, value);
	}

	@Override
	public VarDomain<T> copy() {
		return new VarDomain<>(this.domain, this.map.copy());
	}

	@Override
	public boolean joinInPlace(VarDomain<T> other) {
		return this.map.joinInPlace(other.map);
	}

	@Override
	public boolean supports(PcodeOp op) {
		return this.domain.supports(op);
	}

	@Override
	public VarDomain<T> visit(PcodeOp op) {
		var ret = bottom(this.domain);

		Varnode out = op.getOutput();
		if (out != null) {
			T value = get(out).visit(op, this::get);
			ret.map.put(out, value);
		}

		return ret;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof VarDomain)) {
			return false;
		}

		var other = (VarDomain<?>) obj;
		return this.map.equals(other.map);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.map);
	}

	@Override
	public String toString() {
		return this.map.toString();
	}
}
