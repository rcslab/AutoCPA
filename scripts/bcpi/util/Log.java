package bcpi.util;

import com.google.common.base.Throwables;

/**
 * Simple logging class with formatting support.
 */
public final class Log {
	private static final StackWalker WALKER = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE);
	private static final TtyErrorLogger LOGGER = TtyErrorLogger.INSTANCE;

	private Log() {
	}

	private static String getMessage(Throwable e) {
		return Throwables.getRootCause(e).getMessage();
	}

	public static void trace(String format, Object... args) {
		LOGGER.trace(WALKER.getCallerClass(), String.format(format, args));
	}

	public static void trace(Throwable e) {
		LOGGER.trace(WALKER.getCallerClass(), getMessage(e), e);
	}

	public static void debug(String format, Object... args) {
		LOGGER.debug(WALKER.getCallerClass(), String.format(format, args));
	}

	public static void debug(Throwable e) {
		LOGGER.debug(WALKER.getCallerClass(), getMessage(e), e);
	}

	public static void info(String format, Object... args) {
		LOGGER.info(WALKER.getCallerClass(), String.format(format, args));
	}

	public static void info(Throwable e) {
		LOGGER.info(WALKER.getCallerClass(), getMessage(e), e);
	}

	public static void warn(String format, Object... args) {
		LOGGER.warn(WALKER.getCallerClass(), String.format(format, args));
	}

	public static void warn(Throwable e) {
		LOGGER.warn(WALKER.getCallerClass(), getMessage(e), e);
	}

	public static void error(String format, Object... args) {
		LOGGER.error(WALKER.getCallerClass(), String.format(format, args));
	}

	public static void error(Throwable e) {
		LOGGER.error(WALKER.getCallerClass(), getMessage(e), e);
	}
}
