package bcpi.util;

import java.util.Set;
import java.util.concurrent.atomic.LongAdder;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Stream;

/**
 * Concurrent counter/multiset with long counts.
 */
public final class Counter<T> {
	private final ConcurrentMap<T, LongAdder> map = new ConcurrentHashMap<>();

	/**
	 * @return The count for a key.
	 */
	public long get(T key) {
		LongAdder adder = this.map.get(key);
		if (adder == null) {
			return 0;
		} else {
			return adder.sum();
		}
	}

	/**
	 * Add to the count for a key.
	 */
	public void add(T key, long count) {
		this.map.computeIfAbsent(key, k -> new LongAdder())
			.add(count);
	}

	/**
	 * Increment the count for a key.
	 */
	public void increment(T key) {
		add(key, 1);
	}

	/**
	 * Decrement the count for a key.
	 */
	public void decrement(T key) {
		add(key, -1);
	}

	/**
	 * @return The keys we are counting.
	 */
	public Set<T> keySet() {
		return this.map.keySet();
	}

	/**
	 * A function mapping a key and its count to an object.
	 */
	@FunctionalInterface
	public static interface KeyCountMapper<T, R> {
		R map(T key, long count);
	}

	/**
	 * @return A stream that starts by applying a mapping function.
	 */
	public <R> Stream<R> stream(KeyCountMapper<T, R> mapper) {
		return this.map
			.entrySet()
			.stream()
			.map(e -> mapper.map(e.getKey(), e.getValue().sum()));
	}

	/**
	 * @return A parallel stream that starts by applying a mapping function.
	 */
	public <R> Stream<R> parallelStream(KeyCountMapper<T, R> mapper) {
		return this.map
			.entrySet()
			.parallelStream()
			.map(e -> mapper.map(e.getKey(), e.getValue().sum()));
	}

	@Override
	public String toString() {
		return this.map.toString();
	}
}
