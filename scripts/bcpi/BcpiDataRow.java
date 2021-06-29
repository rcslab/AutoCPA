package bcpi;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Holds a single row of BCPI data.
 */
public class BcpiDataRow {
	public final Address address;
	public final Program program;
	public final Function function;
	public final int count;

	public BcpiDataRow(Address address, Program program, Function function, int count) {
		this.address = address;
		this.program = program;
		this.function = function;
		this.count = count;
	}
}
