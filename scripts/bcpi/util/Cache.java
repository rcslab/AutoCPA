package bcpi.util;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.RecursiveTask;
import java.util.function.Function;

/**
 * Concurrent cache that interoperates with Java's ForkJoinPool.
 */
public final class Cache<K, V> {
	private final ConcurrentMap<K, Task> map = new ConcurrentHashMap<>();
	private final Function<K, V> func;

	private final class Task extends RecursiveTask<V> {
		private final K key;

		Task(K key) {
			this.key = key;
		}

		protected V compute() {
			return func.apply(this.key);
		}
	}

	/**
	 * Create a cache.
	 *
	 * @param func
	 *         The function that computes values from keys.
	 */
	public Cache(Function<K, V> func) {
		this.func = func;
	}

	/**
	 * @retur The (possibly cached) value for this key.
	 */
	public V get(K key) {
		var task = this.map.get(key);
		if (task != null) {
			return task.join();
		}

		var newTask = new Task(key);
		task = this.map.putIfAbsent(key, newTask);
		if (task == null) {
			// We won the race, compute inline
			return newTask.invoke();
		} else {
			// We lost the race, wait
			return task.join();
		}
	}
}
