package bcpi.util;

import com.google.common.collect.Streams;

import java.util.Arrays;
import java.util.Iterator;
import java.util.stream.Stream;

/**
 * Stream utilities.
 */
public final class StreamUtils {
	private StreamUtils() {
	}

	/**
	 * @return A stream for the given array.
	 */
	public static <T> Stream<T> stream(T[] items) {
		return Arrays.stream(items);
	}

	/**
	 * @return A stream for the given iterable.
	 */
	public static <T> Stream<T> stream(Iterable<T> iter) {
		return Streams.stream(iter);
	}

	/**
	 * @return A stream for the given iterator.
	 */
	public static <T> Stream<T> stream(Iterator<T> iter) {
		return Streams.stream(iter);
	}

	/**
	 * Overload to fix ambiguous calls for types that implement both
	 * Iterable and Iterator.
	 *
	 * @return A stream for the given iterable.
	 */
	@SuppressWarnings("unchecked")
	public static <T, U extends Object & Iterable<T> & Iterator<T>> Stream<T> stream(U iter) {
		return stream((Iterable<T>)iter);
	}
}
