package bcpi;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

import com.google.common.collect.HashMultiset;
import com.google.common.collect.Multiset;

import java.util.HashSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Pcode pretty-printer.
 */
public class PcodeFormatter {
	private final AnalysisContext ctx;
	private final Map<Varnode, String> varNames = new HashMap<>();
	private final Multiset<String> varCounts = HashMultiset.create();
	private final HighFunction highFunc;
	private final Function lowFunc;
	private final Program program;
	private final Listing listing;

	public PcodeFormatter(AnalysisContext ctx, HighFunction highFunc) {
		this.ctx = ctx;
		this.highFunc = highFunc;
		this.lowFunc = highFunc.getFunction();
		this.program = this.lowFunc.getProgram();
		this.listing = this.program.getListing();
	}

	/**
	 * Pretty-print a function offset.
	 */
	private void printOffset(Function func, Address addr) {
		var min = func.getEntryPoint();
		var max = func.getBody().getMaxAddress();

		var digits = String.format("%#x", max.subtract(min)).length();
		Tty.print("<<fg=blue>%s</fg>+<fg=yellow>%#0" + digits + "x</fg>>",
			func.getName(), addr.subtract(min));
	}

	/**
	 * Pretty-print an assembly instruction.
	 */
	private void print(Instruction inst) {
		var addr = inst.getAddress();
		Tty.print("  <fg=yellow>%s</fg> ", addr);

		printOffset(this.lowFunc, addr);

		Tty.print(": <b><fg=red>%s</fg></b>\n", inst);
	}

	/**
	 * @return The pretty name of a varnode.
	 */
	private String getName(Varnode vn) {
		return this.varNames.computeIfAbsent(vn, k -> {
			var highName = Optional.of(k)
				.map(Varnode::getHigh)
				.map(HighVariable::getName)
				.orElse("var");
			varCounts.add(highName);
			return highName + "." + varCounts.count(highName);
		});
	}

	/**
	 * Pretty-print a varnode.
	 */
	private void print(Varnode vn) {
		if (vn.getDef() != null) {
			Tty.print("<fg=blue>%s</fg>", getName(vn));
			return;
		}

		if (vn.isConstant()) {
			Tty.print("<fg=yellow>%#x</fg>", vn.getOffset());
			return;
		}

		if (vn.isAddress()) {
			var addr = vn.getAddress();
			var func = this.ctx.getFunctionContaining(addr);
			if (func != null) {
				printOffset(func, addr);
				return;
			}

			var sym = this.ctx.getSymbol(addr);
			if (sym != null) {
				Tty.print("<fg=blue>%s</fg>", sym.getName());
				return;
			}

			Tty.print("<fg=yellow>*%#x</fg>", vn.getOffset());
			return;
		}

		Tty.print("<fg=blue>%s</fg>", getName(vn));
	}

	/**
	 * Pretty-print a varnode with its type, if known.
	 */
	private void printTyped(Varnode vn) {
		var type = Optional.of(vn)
			.map(Varnode::getHigh)
			.map(HighVariable::getDataType);
		if (type.isPresent()) {
			var spec = new StringBuilder();
			var decl = new StringBuilder();
			DataTypes.formatCDecl(type.get(), getName(vn), spec, decl);
			Tty.print("<fg=red>%s</fg> <fg=blue>%s</fg>", spec, decl);
		} else {
			print(vn);
		}
	}

	/**
	 * Pretty-print a pcode op.
	 */
	private void print(PcodeOp op) {
		Tty.print("    ");

		var out = op.getOutput();
		if (out != null) {
			printTyped(out);
			Tty.print("\n      = ");
		}

		Tty.print("<b><fg=green>%s</fg></b>(", op.getMnemonic());

		var comma = false;
		for (var input : op.getInputs()) {
			if (comma) {
				Tty.print(", ");
			}
			comma = true;

			print(input);
		}

		Tty.print(")\n");
	}

	/**
	 * Pretty-print an entire function.
	 */
	public void print() {
		var funcAddr = this.lowFunc.getEntryPoint();
		var funcName = this.lowFunc.getName();
		Tty.print("<fg=yellow>%s</fg> <<fg=blue>%s</fg>>:\n\n", funcAddr, funcName);

		for (var inst : this.listing.getInstructions(this.lowFunc.getBody(), true)) {
			print(inst);

			this.highFunc.getPcodeOps(inst.getAddress())
				.forEachRemaining(this::print);
		}
	}
}
