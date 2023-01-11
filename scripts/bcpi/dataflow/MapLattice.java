package bcpi.dataflow;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

/**
 * A map lattice.
 */
public final class MapLattice<K, V extends Lattice<V>> implements Lattice<MapLattice<K, V>> {
	private final Map<K, V> map;

	private MapLattice(Map<K, V> map) {
		this.map = map;
	}

	/**
	 * @return The empty (bottom) lattice element.
	 */
	public static <L, W extends Lattice<W>> MapLattice<L, W> bottom() {
		return new MapLattice<L, W>(new HashMap<>());
	}

	/**
	 * @return Whether this is the bottom lattice element.
	 */
	public boolean isBottom() {
		return this.map.isEmpty();
	}

	/**
	 * @return The value for the given key, if any.
	 */
	public Optional<V> get(K key) {
		return Optional.ofNullable(this.map.get(key));
	}

	/**
	 * @return The value for the given key, or the result of the given function.
	 */
	public V getOrElse(K key, Function<? super K, ? extends V> func) {
		return get(key).orElseGet(() -> func.apply(key));
	}

	/**
	 * Insert a value into the map.
	 *
	 * @return Whether this map changed.
	 */
	public boolean put(K key, V value) {
		V old = this.map.put(key, value);
		return !value.equals(old);
	}

	@Override
	public MapLattice<K, V> copy() {
		var map = new HashMap<K, V>();
		this.map.forEach((k, v) -> map.put(k, v.copy()));
		return new MapLattice<>(map);
	}

	@Override
	public boolean joinInPlace(MapLattice<K, V> other) {
		// Use an array to allow mutation from inside a closure
		boolean[] ret = {false};

		other.map.forEach((key, theirs) -> {
			this.map.compute(key, (k, ours) -> {
				if (ours == null) {
					ret[0] = true;
					return theirs.copy();
				} else {
					ret[0] |= ours.joinInPlace(theirs);
					return ours;
				}
			});
		});

		return ret[0];
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof MapLattice)) {
			return false;
		}

		var other = (MapLattice<?, ?>) obj;
		return this.map.equals(other.map);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.map);
	}

	@Override
	public String toString() {
		if (isBottom()) {
			return "⊥";
		} else {
			return this.map.toString();
		}
	}
}
