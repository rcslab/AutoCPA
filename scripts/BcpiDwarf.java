/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.dwarf4.next.*;
import ghidra.program.model.data.BuiltInDataTypeManager;

/**
 * Based on Ghidra's DWARF_ExtractorScript, with custom options.
 */
public class BcpiDwarf extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (!DWARFProgram.isDWARF(currentProgram, monitor)) {
			popup("Unable to find DWARF information, aborting");
			return;
		}

		DWARFImportOptions importOptions = new DWARFImportOptions();
		importOptions.setPreloadAllDIEs(true);
		importOptions.setImportLimitDIECount(Integer.MAX_VALUE);
		try (DWARFProgram dwarfProg = new DWARFProgram(currentProgram, importOptions, monitor)) {
			BuiltInDataTypeManager dtms = BuiltInDataTypeManager.getDataTypeManager();
			DWARFParser dp = new DWARFParser(dwarfProg, dtms, monitor);
			DWARFImportSummary importSummary = dp.parse();
			importSummary.logSummaryResults();
		}
	}
}
