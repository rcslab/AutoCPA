package bcpi;

import bcpi.dataflow.BcpiDomain;
import bcpi.dataflow.DataFlow;
import bcpi.dataflow.VarOp;
import bcpi.type.BcpiType;
import bcpi.util.Counter;
import bcpi.util.Tty;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
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
	private final Counter<String> varCounts = new Counter<>();
	private final HighFunction highFunc;
	private final Function lowFunc;
	private final Program program;
	private final Listing listing;
	private final BcpiDomain domain = BcpiDomain.bottom();
	private final DataFlow<BcpiDomain> dataFlow = new DataFlow<>(this.domain);

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
				.filter(n -> !n.equals("UNNAMED"))
				.orElse("var");
			varCounts.increment(highName);
			return highName + "." + varCounts.get(highName);
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
	 * Pretty print a name with a type.
	 */
	private void printTyped(DataType type, String name) {
		var spec = new StringBuilder();
		var prefix = new StringBuilder();
		var suffix = new StringBuilder();
		BcpiType.from(type).toC(spec, prefix, suffix);
		Tty.print("<fg=red>%s %s</fg><fg=blue>%s</fg><fg=red>%s</fg>", spec, prefix, name, suffix);
	}

	/**
	 * Pretty-print a varnode with its type, if known.
	 */
	private void printTyped(Varnode vn) {
		var type = Optional.of(vn)
			.map(Varnode::getHigh)
			.map(HighVariable::getDataType);
		if (type.isPresent()) {
			printTyped(type.get(), getName(vn));
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
			Tty.print(" = ");
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
	 * Pretty-print the function's signature.
	 */
	private void printSignature() {
		var addr = this.lowFunc.getEntryPoint();
		Tty.print("<fg=yellow>%s</fg> ", addr);

		var type = this.lowFunc.getReturnType();
		var name = this.lowFunc.getName();
		printTyped(type, name);

		Tty.print("(");
		var locals = this.highFunc.getLocalSymbolMap();
		for (int i = 0; i < locals.getNumParams(); ++i) {
			if (i > 0) {
				Tty.print(", ");
			}
			var param = locals.getParam(i);
			if (param != null) {
				printTyped(param.getRepresentative());
			}
		}
		Tty.print(")\n\n");
	}

	/**
	 * Pretty-print an entire function.
	 */
	public void print() {
		printSignature();

		for (var inst : this.listing.getInstructions(this.lowFunc.getBody(), true)) {
			print(inst);

			this.highFunc.getPcodeOps(inst.getAddress())
				.forEachRemaining(this::print);
		}
	}

	/**
	 * @return The data flow facts for a varnode.
	 */
	private BcpiDomain getFacts(Varnode vn) {
		return this.dataFlow.fixpoint(vn);
	}

	/**
	 * Pretty-print the data flow through an instruction.
	 */
	public void printDataFlow(Address addr) {
		printSignature();

		var vops = new ArrayList<VarOp>();
		var seen = new HashSet<VarOp>();

		this.highFunc.getPcodeOps(addr).forEachRemaining(op -> {
			var vn = op.getOutput();
			if (vn != null) {
				var vop = new VarOp(vn, op);
				vops.add(vop);
				seen.add(vop);
			}
		});

		// Dependency-order the per-instruction pcode ops
		var order = Comparator
			.<VarOp>comparingInt(vop -> vop.getSeqnum().getOrder())
			.reversed();
		Collections.sort(vops, order);

		for (int i = 0; i < vops.size(); ++i) {
			var vop = vops.get(i);
			var inputs = new ArrayList<>(this.domain.getInputs(vop));
			Collections.reverse(inputs);
			for (var input : inputs) {
				if (input.getOp() != null && seen.add(input)) {
					vops.add(input);
				}
			}
		}

		if (vops.isEmpty()) {
			print(this.listing.getInstructionAt(addr));
			Tty.print("    No pcode\n");
			return;
		}

		Address lastAddr = null;
		Collections.reverse(vops);
		for (var vop : vops) {
			var op = vop.getOp();
			var opAddr = op.getSeqnum().getTarget();
			if (!opAddr.equals(lastAddr)) {
				print(this.listing.getInstructionAt(opAddr));
				lastAddr = opAddr;
			}

			Tty.print("      ");

			var out = vop.getVar();
			printTyped(out);

			Tty.print(" = <b><fg=green>%s</fg></b>(", op.getMnemonic());
			var inputs = op.getInputs();
			if (inputs.length > 0) {
				Tty.print("\n");
				for (var input : inputs) {
					Tty.print("        ");
					print(input);
					Tty.print(" = <i>%s</i>,\n", getFacts(input));
				}
				Tty.print("      ");
			}
			Tty.print(")\n");
			Tty.print("      = <b>%s</b>\n", getFacts(out));
		}
	}
}
