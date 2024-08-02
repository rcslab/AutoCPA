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
	private final boolean locked;

	private final class Task extends RecursiveTask<V> {
		private final K key;

		Task(K key) {
			this.key = key;
		}

		protected V compute() {
			return func.apply(this.key);
		}
	}

	private Cache(Function<K, V> func, boolean locked) {
		this.func = func;
		this.locked = locked;
	}

	/**
	 * Create a locked cache.
	 *
	 * The given function will be invoked at most once for each key.
	 * Concurrent queries for the same key will block.
	 *
	 * @param func
	 *         The function that computes values from keys.
	 */
	public static <K, V> Cache<K, V> locked(Function<K, V> func) {
		return new Cache<>(func, true);
	}

	/**
	 * Create an unlocked cache.
	 *
	 * The function may be invoked multiple times if the same key is queried
	 * concurrently, but only one return value will be used.
	 *
	 * @param func
	 *         The function that computes values from keys.
	 */
	public static <K, V> Cache<K, V> unlocked(Function<K, V> func) {
		return new Cache<>(func, false);
	}

	/**
	 * @return The (possibly cached) value for this key.
	 */
	public V get(K key) {
		var task = this.map.get(key);
		if (task != null) {
			return task.join();
		}

		var newTask = new Task(key);

		if (!this.locked) {
			// Compute the value (potentially concurrently with other lookups for key)
			newTask.invoke();
		}

		task = this.map.putIfAbsent(key, newTask);
		if (task == null) {
			task = newTask;
			if (this.locked) {
				// We won the race, so we are the unique task for this key
				task.invoke();
			}
		}

		return task.join();
	}
}
