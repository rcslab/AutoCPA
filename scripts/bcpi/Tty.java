package bcpi;

import java.util.Map;

/**
 * Utilities for TTY formatting.
 */
public class Tty {
	/** Whether standard output is a TTY. */
	public static final boolean IS_A_TTY = System.console() != null;

	private static final Map<String, String> COLORS = Map.ofEntries(
		Map.entry("<b>", "\033[1m"),
		Map.entry("</b>", "\033[22m"),

		Map.entry("<i>", "\033[3m"),
		Map.entry("</i>", "\033[23m"),

		Map.entry("<u>", "\033[4m"),
		Map.entry("</u>", "\033[24m"),

		Map.entry("<fg=red>", "\033[31m"),
		Map.entry("<fg=green>", "\033[32m"),
		Map.entry("<fg=yellow>", "\033[33m"),
		Map.entry("<fg=blue>", "\033[34m"),
		Map.entry("<fg=magenta>", "\033[35m"),
		Map.entry("<fg=cyan>", "\033[36m"),
		Map.entry("</fg>", "\033[39m"),

		Map.entry("<bg=red>", "\033[41m"),
		Map.entry("<bg=green>", "\033[42m"),
		Map.entry("<bg=yellow>", "\033[43m"),
		Map.entry("<bg=blue>", "\033[44m"),
		Map.entry("<bg=magenta>", "\033[45m"),
		Map.entry("<bg=cyan>", "\033[46m"),
		Map.entry("</bg>", "\033[49m")
	);

	private Tty() {
	}

	public static void print(String format, Object... args) {
		for (var color : COLORS.entrySet()) {
			var key = color.getKey();
			var value = IS_A_TTY ? color.getValue() : "";
			format = format.replace(key, value);
		}
		System.out.format(format, args);
	}
}
