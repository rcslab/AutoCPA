package bcpi;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import com.google.common.collect.Multiset;
import com.google.common.collect.ImmutableMultiset;

/**
 * Holds a single row of BCPI data.
 */
public class BcpiDataRow {
	public final Address address;
	public final Program program;
	public final Function function;
	public final Multiset<String> counters;

	public BcpiDataRow(Address address, Program program, Function function, Multiset<String> counters) {
		this.address = address;
		this.program = program;
		this.function = function;
		this.counters = ImmutableMultiset.copyOf(counters);
	}

	/**
	 * Get the value of a particular counter for this row.
	 */
	public int getCount(String counter) {
		return this.counters.count(counter);
	}
}
