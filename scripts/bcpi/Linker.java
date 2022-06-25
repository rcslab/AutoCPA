package bcpi;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.util.Msg;

import com.google.common.collect.ImmutableList;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * "Dynamic linker" for external functions.
 */
public class Linker {
	private final List<Program> programs;
	private final ConcurrentMap<String, Optional<Function>> cache;

	public Linker(Collection<Program> programs) {
		this.programs = ImmutableList.copyOf(programs);
		this.cache = new ConcurrentHashMap<>();
	}

	/**
	 * @return The programs known to this linker.
	 */
	public List<Program> getPrograms() {
		return this.programs;
	}

	/**
	 * Resolve a possibly external function.
	 */
	public Optional<Function> resolve(Function func) {
		Function resolved = func;
		if (resolved.isThunk()) {
			resolved = resolved.getThunkedFunction(true);
		}

		if (!resolved.isExternal()) {
			return Optional.of(resolved);
		}

		ExternalLocation loc = resolved.getExternalLocation();
		String name = loc.getOriginalImportedName();
		if (name == null) {
			name = loc.getLabel();
		}

		return this.cache.computeIfAbsent(name, k -> this.programs
			.stream()
			.flatMap(p -> p
				.getSymbolTable()
				.getGlobalSymbols(k)
				.stream()
				.map(s -> p.getFunctionManager().getFunctionAt(s.getAddress())))
			.filter(f -> f != null)
			.filter(f -> !f.isThunk())
			.filter(f -> !f.isExternal())
			.findFirst()
			.or(() -> {
				Msg.warn(this, "Couldn't resolve function " + func);
				return Optional.empty();
			}));
	}
}
