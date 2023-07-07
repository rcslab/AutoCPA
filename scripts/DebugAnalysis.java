import bcpi.BcpiAnalysis;
import bcpi.BcpiConfig;
import bcpi.BcpiControlFlow;
import bcpi.BcpiData;
import bcpi.BcpiDataRow;
import bcpi.FieldReferences;
import bcpi.PcodeFormatter;

import java.nio.file.Paths;
import java.util.Comparator;

/**
 * Utility for debugging BCPI analysis.
 */
public class DebugAnalysis extends BcpiAnalysis {
	@Override
	protected void analyze(String[] args) throws Exception {
		for (var arg : args) {
			if (arg.startsWith("pcode:")) {
				debugPcode(arg.substring(6));
			} else if (arg.startsWith("dataflow:")) {
				debugDataFlow(arg.substring(9));
			} else if (arg.startsWith("csv:")) {
				debugCsv(arg.substring(4));
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

	private void debugDataFlow(String inst) {
		var ctx = getContext();
		var decomp = ctx.getDecompiler();
		var addr = ctx.getAddress(inst);
		var func = ctx.getFunctionContaining(addr);
		var highFunc = decomp.decompile(func);
		new PcodeFormatter(ctx, highFunc).printDataFlow(addr);
	}

	private void debugCsv(String csv) throws Exception {
		var ctx = getContext();
		var path = Paths.get(csv);
		var data = BcpiData.parse(path, ctx);
		var cfgs = new BcpiControlFlow(ctx);
		var refs = new FieldReferences(ctx, cfgs);
		refs.collect(data.getFunctions());
		data.getRows()
			.stream()
			.filter(r -> refs.getFields(r.address).isEmpty())
			.sorted(Comparator.<BcpiDataRow>comparingInt(r -> -r.getCount(BcpiConfig.CACHE_MISS_COUNTER)))
			.limit(10)
			.forEach(r -> {
				System.out.format("%s: %d samples, no struct fields\n",
					r.address, r.getCount(BcpiConfig.CACHE_MISS_COUNTER));
			});
	}
}
