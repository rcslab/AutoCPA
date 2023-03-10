import bcpi.BcpiAnalysis;
import bcpi.PcodeFormatter;

/**
 * Utility for debugging BCPI analysis.
 */
public class DebugAnalysis extends BcpiAnalysis {
	@Override
	protected void analyze(String[] args) {
		for (var arg : args) {
			if (arg.startsWith("pcode:")) {
				debugPcode(arg.substring(6));
			} else {
				throw new IllegalArgumentException(arg);
			}
		}
	}

	private void debugPcode(String name) {
		var ctx = getContext();
		var decomp = ctx.getDecompiler();

		for (var func : ctx.getFunctionsNamed(name)) {
			var highFunc = decomp.decompile(func);
			new PcodeFormatter(ctx, highFunc).print();
		}
	}
}
