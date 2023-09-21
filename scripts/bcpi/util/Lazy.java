package bcpi.util;

import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * A lazily-initialized reference.
 */
public final class Lazy<T> implements Supplier<T> {
	private final AtomicReference<T> ref = new AtomicReference<>();
	private final Supplier<T> init;

	/**
	 * Create a lazy reference.
	 *
	 * @param init
	 *         The function that initializes this reference.
	 */
	public Lazy(Supplier<T> init) {
		this.init = init;
	}

	@Override
	public T get() {
		T val = this.ref.get();
		if (val != null) {
			return val;
		}

		T newVal = this.init.get();
		val = this.ref.compareAndExchange(null, newVal);
		if (val == null) {
			return newVal;
		} else {
			return val;
		}
	}
}
