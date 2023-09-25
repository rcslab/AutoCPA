package bcpi;

import bcpi.util.TtyErrorLogger;

import ghidra.app.script.GhidraScript;
import ghidra.util.Msg;

/**
 * Base class for BCPI analyses.
 */
public abstract class BcpiAnalysis extends GhidraScript {
	static {
		Msg.setErrorLogger(TtyErrorLogger.INSTANCE);
	}

	private AnalysisContext ctx = null;

	/**
	 * Run the analysis.
	 */
	protected abstract void analyze(String[] args) throws Exception;

	/**
	 * @return The analysis context.
	 */
	protected AnalysisContext getContext() {
		return this.ctx;
	}

	@Override
	public final void run() throws Exception {
		this.ctx = new AnalysisContext(getState().getProject(), this.monitor);

		analyze(getScriptArgs());
	}
}
