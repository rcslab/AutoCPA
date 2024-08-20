package bcpi.util;

import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Set;

/**
 * A double-ended queue for work-list algorithms.
 */
public final class WorkList<T> {
	private final ArrayDeque<T> deque = new ArrayDeque<>();
	private final Set<T> set = new HashSet<>();

	/**
	 * @return Whether any items are in the list.
	 */
	public boolean isEmpty() {
		return this.deque.isEmpty();
	}

	/**
	 * @return Whether this list already contains the item.
	 */
	public boolean contains(T item) {
		return this.set.contains(item);
	}

	/**
	 * Add an item to the front of the queue.
	 *
	 * @return Whether a new item was added.
	 */
	public boolean addFirst(T item) {
		if (this.set.add(item)) {
			this.deque.addFirst(item);
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Add an item to the back of the queue.
	 *
	 * @return Whether a new item was added.
	 */
	public boolean addLast(T item) {
		if (this.set.add(item)) {
			this.deque.addLast(item);
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Pop an element from the front of the queue.
	 */
	public T removeFirst() {
		var ret = this.deque.removeFirst();
		this.set.remove(ret);
		return ret;
	}

	/**
	 * Pop an element from the back of the queue.
	 */
	public T removeLast() {
		var ret = this.deque.removeLast();
		this.set.remove(ret);
		return ret;
	}
}
