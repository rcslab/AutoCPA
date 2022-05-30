package bcpi;

/**
 * BCPI analysis configuration.
 */
public class BcpiConfig {
	/** Counter to use for cache misses. */
	public static final String CACHE_MISS_COUNTER = stringEnv("BCPI_CACHE_MISS_COUNTER", BcpiCounters.DC_MISSES);
	/** Counter to use for retired instructions. */
	public static final String INSTRUCTION_COUNTER = stringEnv("BCPI_INSTRUCTION_COUNTER", BcpiCounters.INSTRUCTIONS);

	/** Whether to analyze control flow before samples. */
	public static final boolean ANALYZE_BACKWARD_FLOW = !checkEnv("BCPI_NO_BACKWARD_FLOW");
	/** Whether to analyze control flow after samples. */
	public static final boolean ANALYZE_FORWARD_FLOW = !checkEnv("BCPI_NO_FORWARD_FLOW");

	/** Inter-procedural analysis depth. */
	public static final int IPA_DEPTH = intEnv("BCPI_IPA_DEPTH", 1);
	/** Maximum function size for IPA. */
	public static final int MAX_INLINE_SIZE = intEnv("BCPI_MAX_INLINE_SIZE", 1024);

	/** Maximum beam width during beam search. */
	public static final int BEAM_WIDTH = intEnv("BCPI_BEAM_WIDTH", 5);
	/** Number of paths to use from beam search. */
	public static final int BEAM_PATHS = intEnv("BCPI_BEAM_PATHS", 1);

	/** Whether to assume structures are allocated at the beginning of cache lines. */
	public static final boolean ASSUME_CACHE_ALIGNED = checkEnv("BCPI_ASSUME_CACHE_ALIGNED");

	/**
	 * Check if a setting has been enabled through an environment variable.
	 */
	private static boolean checkEnv(String var) {
		String value = System.getenv(var);
		return value != null && !value.isEmpty();
	}

	/**
	 * Get a string value from the environment.
	 */
	private static String stringEnv(String var, String def) {
		String value = System.getenv(var);
		if (value != null && !value.isEmpty()) {
			return value;
		} else {
			return def;
		}
	}

	/**
	 * Get an integer value from the environment.
	 */
	private static int intEnv(String var, int def) {
		String value = System.getenv(var);
		if (value != null && !value.isEmpty()) {
			return Integer.parseInt(value);
		} else {
			return def;
		}
	}
}
