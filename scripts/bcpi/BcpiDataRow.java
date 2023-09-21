package bcpi;

import bcpi.util.Counter;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.stream.Collectors;

/**
 * Holds a single row of BCPI data.
 */
public class BcpiDataRow {
	public final Address address;
	public final Program program;
	public final Function function;
	public final Counter<String> counters;

	public BcpiDataRow(Address address, Program program, Function function, Counter<String> counters) {
		this.address = address;
		this.program = program;
		this.function = function;
		this.counters = counters;
	}

	/**
	 * Get the value of a particular counter for this row.
	 */
	public long getCount(String counter) {
		return this.counters.get(counter);
	}

	@Override
	public String toString() {
		var prefix = this.address + ",";
		return this.counters
			.stream((k, c) -> k + "=" + c)
			.collect(Collectors.joining(",", prefix, ""));
	}
}
