package bcpi;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * An analysis context manages one or more programs that are linked together.
 */
public class AnalysisContext {
	private final Project project;
	private final TaskMonitor monitor;
	private final Collection<Program> programs;
	private final BcpiDecompiler decomp;
	private final Linker linker;

	AnalysisContext(Project project, TaskMonitor monitor) throws Exception {
		this.project = project;
		this.monitor = monitor;
		this.programs = findPrograms();
		this.decomp = new BcpiDecompiler(project);
		this.linker = new Linker(this.programs);
	}

	private Collection<Program> findPrograms() throws Exception {
		var programs = new ArrayList<Program>();

		var folders = new ArrayDeque<DomainFolder>();
		folders.add(this.project.getProjectData().getRootFolder());

		while (!folders.isEmpty()) {
			var folder = folders.removeFirst();

			for (var file : folder.getFiles()) {
				var object = file.getImmutableDomainObject(this, DomainFile.DEFAULT_VERSION, this.monitor);
				if (object instanceof Program) {
					programs.add((Program) object);
				} else {
					object.release(this);
				}
			}

			for (var subFolder : folder.getFolders()) {
				folders.addLast(subFolder);
			}
		}

		return List.copyOf(programs);
	}

	/**
	 * @return The current Ghidra project.
	 */
	public Project getProject() {
		return this.project;
	}

	/**
	 * @return The current task monitor.
	 */
	public TaskMonitor getMonitor() {
		return this.monitor;
	}

	/**
	 * @return All the programs (executables, libraries, kernel modules).
	 */
	public Collection<Program> getPrograms() {
		return this.programs;
	}

	/**
	 * @return A decompiler for this context.
	 */
	public BcpiDecompiler getDecompiler() {
		return this.decomp;
	}

	/**
	 * @return The linker for resolving function calls between programs.
	 */
	public Linker getLinker() {
		return this.linker;
	}

	/**
	 * @return All the functions with the given name.
	 */
	public Collection<Function> getFunctionsNamed(String name) {
		return this.programs.stream()
			.map(Program::getFunctionManager)
			.map(fm -> fm.getFunctions(true))
			.<Function>mapMulti((funcs, stream) -> funcs.forEach(stream::accept))
			.filter(f -> f.getName().equals(name))
			.collect(Collectors.toList());
	}

	/**
	 * @return The given string as an address.
	 */
	public Address getAddress(String addr) {
		return this.programs.stream()
			.map(Program::getAddressFactory)
			.map(af -> af.getAddress(addr))
			.filter(Objects::nonNull)
			.findAny()
			.orElse(null);
	}

	/**
	 * @return The function containing the given address, if any.
	 */
	public Function getFunctionContaining(Address addr) {
		return this.programs.stream()
			.map(Program::getListing)
			.map(l -> l.getFunctionContaining(addr))
			.filter(Objects::nonNull)
			.findAny()
			.orElse(null);
	}

	/**
	 * @return The symbol at the given address, if any.
	 */
	public Symbol getSymbol(Address addr) {
		return this.programs.stream()
			.map(Program::getSymbolTable)
			.map(t -> t.getPrimarySymbol(addr))
			.filter(Objects::nonNull)
			.findAny()
			.orElse(null);
	}
}
