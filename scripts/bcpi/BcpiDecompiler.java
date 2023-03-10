package bcpi;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileProcess;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.model.Project;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.DecoderException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PackedDecode;
import ghidra.program.model.pcode.PcodeDataTypeManager;
import ghidra.program.model.symbol.IdentityNameTransformer;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import com.google.common.base.Throwables;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;

/**
 * Wrapper around Ghidra's decompiler.
 */
public class BcpiDecompiler {
	/** The path to the on-disk cache directory. */
	private final Path diskCache;
	/** The active decompiler processes. */
	private final ConcurrentMap<Program, Queue<CachingDecompiler>> decompilers = new ConcurrentHashMap<>();
	/** Cache of failed decompilations. */
	private final Set<Function> failed = ConcurrentHashMap.newKeySet();

	/**
	 * Create a BcpiDecompiler for the given project.
	 */
	BcpiDecompiler(Project project) {
		this.diskCache = project.getProjectLocator().getProjectDir().toPath().resolve("decomp");
	}

	/**
	 * @return The path to the cached decompilation of the given function.
	 */
	private Path getCachePath(Function func) {
		return this.diskCache.resolve(String.valueOf(func.getID()));
	}

	/**
	 * Decompile the given function.
	 */
	public HighFunction decompile(Function func) {
		if (failed.contains(func)) {
			return null;
		}

		HighFunction result = null;
		try {
			result = checkDiskCache(func);
		} catch (Throwable e) {
			while (e.getClass() == RuntimeException.class) {
				var cause = e.getCause();
				if (cause == null) {
					break;
				} else {
					e = cause;
				}
			}
			Msg.error(this, "Error decompiling " + func.getName(), e);
		}

		if (result == null) {
			failed.add(func);
		}
		return result;
	}

	/**
	 * Check the on-disk cache for decompilation results.
	 */
	private HighFunction checkDiskCache(Function func) {
		var path = getCachePath(func);
		if (!Files.exists(path)) {
			return invokeDecompiler(func);
		}

		try (var stream = new BufferedInputStream(Files.newInputStream(path))) {
			var program = func.getProgram();
			var decoder = new PackedDecode(program.getAddressFactory());
			decoder.open(128 << 20, path.toString());

			while (true) {
				stream.mark(1);
				int b = stream.read();
				if (b < 0) {
					break;
				}
				stream.reset();
				decoder.ingestStream(stream);
			}

			decoder.endIngest();

			var lang = program.getLanguage();
			var cspec = program.getCompilerSpec();
			var dtManager = new PcodeDataTypeManager(program, new IdentityNameTransformer());
			var results = new DecompileResults(func, lang, cspec, dtManager, "", decoder, DecompileProcess.DisposeState.NOT_DISPOSED);
			return results.getHighFunction();
		} catch (Exception e) {
			Throwables.throwIfUnchecked(e);
			throw new RuntimeException(e);
		}
	}

	/**
	 * Invoke the actual decompiler on a cache miss.
	 */
	private HighFunction invokeDecompiler(Function func) {
		var program = func.getProgram();
		var queue = this.decompilers.computeIfAbsent(program, p -> new ConcurrentLinkedQueue<>());

		var decomp = queue.poll();
		if (decomp == null) {
			decomp = new CachingDecompiler(program);
		}

		try {
			var timeout = decomp.getOptions().getDefaultTimeout();
			var results = decomp.decompileFunction(func, timeout, TaskMonitor.DUMMY);

			String error = results.getErrorMessage().strip();
			if (!results.decompileCompleted()) {
				Msg.error(this, func.getName() + ": " + error);
			} else if (!error.isEmpty()) {
				Msg.warn(this, func.getName() + ": " + error);
			}

			return results.getHighFunction();
		} finally {
			queue.offer(decomp);
		}
	}

	/**
	 * A decompiler subclass that caches results.
	 */
	private class CachingDecompiler extends DecompInterface {
		CachingDecompiler(Program program) {
			toggleCCode(true);
			toggleSyntaxTree(true);
			setSimplificationStyle("decompile");

			var xmlOptions = new DecompileOptions();
			xmlOptions.setDefaultTimeout(60);
			xmlOptions.setMaxPayloadMBytes(128);
			setOptions(xmlOptions);

			openProgram(program);
		}

		@Override
		public DecompileResults decompileFunction(Function func, int timeout, TaskMonitor monitor) {
			var program = func.getProgram();
			var addrFactory = program.getAddressFactory();
			var path = getCachePath(func);
			this.baseEncodingSet.mainResponse = new CachingDecoder(addrFactory, path);

			return super.decompileFunction(func, timeout, monitor);
		}
	}

	/**
	 * A decoder that caches the decompiler response.
	 */
	private static class CachingDecoder extends PackedDecode {
		private final Path path;
		private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

		CachingDecoder(AddressFactory addrFactory, Path path) {
			super(addrFactory);
			this.path = path;
		}

		@Override
		public void clear() {
			this.buffer.reset();
			super.clear();
		}

		@Override
		public void open(int max, String source) {
			this.buffer.reset();
			super.open(max, source);
		}

		@Override
		public void ingestStream(InputStream stream) throws IOException {
			// Ingest bytes from the stream up to (and including) the first 0 byte.
			var chunk = new ByteArrayOutputStream();
			while (true) {
				int b = stream.read();
				if (b < 0) {
					break;
				}

				chunk.write(b);
				if (b == 0) {
					break;
				}
			}
			chunk.writeTo(this.buffer);

			super.ingestStream(new ByteArrayInputStream(chunk.toByteArray()));
		}

		@Override
		public void endIngest() {
			try {
				// Cache the response to disk
				var dir = this.path.getParent();
				Files.createDirectories(dir);
				var tmp = Files.createTempFile(dir, null, null);
				try (var out = Files.newOutputStream(tmp)) {
					this.buffer.writeTo(out);
				}
				Files.move(tmp, this.path, StandardCopyOption.REPLACE_EXISTING);

				super.endIngest();
			} catch (Exception e) {
				Throwables.throwIfUnchecked(e);
				throw new RuntimeException(e);
			}
		}
	}
}
