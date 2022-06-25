package bcpi;

/**
 * A generic cost model.
 */
@FunctionalInterface
public interface CostModel<T> {
	/**
	 * @return The cost of the given instance.
	 */
	long cost(T object);
}
