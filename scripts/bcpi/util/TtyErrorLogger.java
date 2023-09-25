package bcpi.util;

import ghidra.util.ErrorLogger;

import com.google.common.base.Throwables;

/**
 * Ghidra logging backend with colors.
 */
public final class TtyErrorLogger implements ErrorLogger {
	public static final TtyErrorLogger INSTANCE = new TtyErrorLogger();

	private TtyErrorLogger() {
	}

	private void header(String level, String tag, String line) {
		switch (level) {
		case "INFO":
			Tty.print("<fg=cyan><b>%-5s</b> <i>%-20s</i></fg> %s\n", level, tag, line);
			break;
		case "WARN":
			Tty.print("<fg=yellow><b>%-5s</b> <i>%-20s</i> <b>%s</b></fg>\n", level, tag, line);
			break;
		case "ERROR":
			Tty.print("<fg=red><b>%-5s</b> <i>%-20s</i> <b>%s</b></fg>\n", level, tag, line);
			break;
		default:
			Tty.print("<fg=gray><b>%-5s</b> <i>%-20s</i> %s</fg>\n", level, tag, line);
			break;
		}
	}

	private void trailer(String level, String line) {
		switch (level) {
		case "INFO":
			Tty.print("%s\n", line);
			break;
		case "WARN":
			Tty.print("<fg=yellow><b>%s</b></fg>\n", line);
			break;
		case "ERROR":
			Tty.print("<fg=red><b>%s</b></fg>\n", line);
			break;
		default:
			Tty.print("<fg=gray>%s</fg>\n", line);
			break;
		}
	}

	private void stackTrace(String level, String line) {
		switch (level) {
		case "INFO":
			Tty.print("<fg=cyan>%s</fg>\n", line);
			break;
		case "WARN":
			Tty.print("<fg=yellow>%s</fg>\n", line);
			break;
		case "ERROR":
			Tty.print("<fg=red>%s</fg>\n", line);
			break;
		default:
			Tty.print("<fg=gray>%s</fg>\n", line);
			break;
		}
	}

	private synchronized void log(String level, Object src, Object msg, Throwable e) {
		String tag;
		if (src instanceof String s) {
			tag = s;
		} else if (src instanceof Class<?> c) {
			tag = c.getSimpleName();
		} else {
			tag = src.getClass().getSimpleName();
		}

		var str = String.valueOf(msg);
		if (str.contains("\n")) {
			header(level, tag, "");
			str.lines()
				.forEach(line -> trailer(level, line));
		} else {
			header(level, tag, str);
		}

		if (e != null) {
			Throwables.getStackTraceAsString(e)
				.lines()
				.forEach(line -> stackTrace(level, line));
		}
	}

	@Override
	public void trace(Object src, Object msg) {
		// trace(src, msg, null);
	}

	@Override
	public void trace(Object src, Object msg, Throwable e) {
		// log("TRACE", src, msg, e);
	}

	@Override
	public void debug(Object src, Object msg) {
		debug(src, msg, null);
	}

	@Override
	public void debug(Object src, Object msg, Throwable e) {
		log("DEBUG", src, msg, e);
	}

	@Override
	public void info(Object src, Object msg) {
		info(src, msg, null);
	}

	@Override
	public void info(Object src, Object msg, Throwable e) {
		log("INFO", src, msg, e);
	}

	@Override
	public void warn(Object src, Object msg) {
		warn(src, msg, null);
	}

	@Override
	public void warn(Object src, Object msg, Throwable e) {
		log("WARN", src, msg, e);
	}

	@Override
	public void error(Object src, Object msg) {
		error(src, msg, null);
	}

	@Override
	public void error(Object src, Object msg, Throwable e) {
		log("ERROR", src, msg, e);
	}
}
