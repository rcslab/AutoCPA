package bcpi;

/**
 * BCPI analysis configuration.
 */
public class BcpiConfig {
	/** Whether to analyze control flow before samples. */
	public static final boolean ANALYZE_BACKWARD_FLOW = !checkEnv("BCPI_NO_BACKWARD_FLOW");
	/** Whether to analyze control flow after samples. */
	public static final boolean ANALYZE_FORWARD_FLOW = !checkEnv("BCPI_NO_FORWARD_FLOW");
	/** Inter-procedural analysis depth. */
	public static final int IPA_DEPTH = intEnv("BCPI_IPA_DEPTH", 1);
	/** Maximum function size for IPA. */
	public static final int MAX_INLINE_SIZE = intEnv("BCPI_MAX_INLINE_SIZE", 1024);
	/** Whether to use coverage information. */
	public static final boolean USE_COVERAGE = !checkEnv("BCPI_NO_COVERAGE");
	/** Maximum beam width during beam search. */
	public static final int BEAM_WIDTH = intEnv("BCPI_BEAM_WIDTH", 5);
	/** Number of paths to use from beam search. */
	public static final int BEAM_PATHS = intEnv("BCPI_BEAM_PATHS", 1);

	/**
	 * Check if a setting has been enabled through an environment variable.
	 */
	private static boolean checkEnv(String var) {
		String value = System.getenv(var);
		return value != null && !value.isEmpty();
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
