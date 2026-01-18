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
package nativeaot;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import nativeaot.objectmodel.FrozenObjectAnnotator;
import nativeaot.objectmodel.MethodTableCrawler;
import nativeaot.objectmodel.net80.MethodTableManagerNet80;
import nativeaot.rehydration.MetadataRehydrator;
import nativeaot.rehydration.MetadataRehydratorNet80;
import nativeaot.rehydration.PointerScanResult;
import nativeaot.rtr.ReadyToRunDirectory;
import nativeaot.rtr.ReadyToRunLocator;
import nativeaot.rtr.ReadyToRunSection;
import nativeaot.rtr.SymbolReadyToRunLocator;

/**
 * Provide class-level documentation that describes what this analyzer does.
 */
public class NativeAotAnalyzer extends AbstractAnalyzer {

    public static final String MARKUP_REHYDRATION_CODE = "Markup rehydration code";

    private boolean _markupRehydrationCode = false;

    public NativeAotAnalyzer() {
        super(
            Constants.NAME,
            "Analyzes binaries compiled using .NET Native AOT technology.",
            AnalyzerType.BYTE_ANALYZER
        );
        setSupportsOneTimeAnalysis();
        setPriority(AnalysisPriority.LOW_PRIORITY);
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        return false;
    }

    @Override
    public boolean canAnalyze(Program program) {
        // We currently only support x86-64.
        if (!program.getLanguageID().getIdAsString().startsWith("x86:LE:64")) {
            return false;
        }

        return true;
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(
            MARKUP_REHYDRATION_CODE,
            false,
            null,
            "Label all opcodes in the program that is responsible for decompressing the hydrated metadata."
        );
    }

    @Override
    public void optionsChanged(Options options, Program program) {
        _markupRehydrationCode = options.getBoolean(MARKUP_REHYDRATION_CODE, false);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {

        // TODO: make configurable which locator is used..
        ReadyToRunLocator locator = new SymbolReadyToRunLocator();

        var moduleHeaders = locator.locateModules(program, monitor, log);

        if (moduleHeaders.length == 0) {
            log.appendMsg(Constants.TAG, String.format(
                "Symbols `%s` or `%s` and `%s` not found.",
                Constants.READY_TO_RUN_HEADER_SYMBOL_NAME,
                Constants.READY_TO_RUN_MODULES_START_SYMBOL_NAME,
                Constants.READY_TO_RUN_MODULES_END_SYMBOL_NAME
            ));
            log.appendMsg(Constants.TAG, "A reference of these can be found as the second argument of the call to `StartupCodeHelpers__InitializeModules` in the main function.");
            return false;
        }

        // Process all modules.
        for (var moduleHeader : moduleHeaders) {
            if (moduleHeader.getOffset() == 0) {
                continue;
            }

            try {
                processModule(program, moduleHeader, monitor, log);
            } catch (Exception ex) {
                log.appendMsg(Constants.TAG,"Failed to process module header " + moduleHeader);
                log.appendException(ex);
            }
        }

        return true;
    }

    private void processModule(Program program, Address moduleHeader, TaskMonitor monitor, MessageLog log) throws Exception {
        ReadyToRunDirectory directory;
        try {
            directory = readRtrDirectory(program, moduleHeader);
        } catch (Exception ex) {
            throw new Exception("Failed to read rtr directory.", ex);
        }

        // NOTE: Method table managers should be changed if the file format changes per rtr version.
        var manager = new MethodTableManagerNet80(program);

        // Restore first from DB to allow for the analyzer to be run multiple times.
        manager.restoreFromDB();

        // Find the dehydrated section (.NET 8.0+).
        PointerScanResult pointerScan;
        var section = directory.getSectionByType(ReadyToRunSection.DEHYDRATED_DATA);
        if (section == null) {
            // Fallback for .NET 7.0 / 10.0+: Scan memory for pointers manually.
            log.appendMsg(Constants.TAG, "No dehydrated data found. Attempting manual pointer scan.");
            try {
                pointerScan = scanForPointers(program, moduleHeader, monitor, log);
            } catch (Exception ex) {
                throw new Exception("Manual scan failed.", ex);
            }
        } else {
            try {
                // NOTE: Metadata rehydrators should be changed if the file format changes per rtr version.
                var rehydrator = new MetadataRehydratorNet80();
                rehydrator.markupRehydrationCode(_markupRehydrationCode);
                pointerScan = rehydrateData(program, section, rehydrator, monitor, log);
                log.appendMsg(Constants.TAG, "Rehydrated " + pointerScan.getScanningRange());
            } catch (Exception ex) {
                throw new Exception("Rehydration failed.", ex);
            }
        }

        // Find all method tables.
        try {
            var crawler = new MethodTableCrawler(manager, program, pointerScan);
            crawler.analyze(monitor, log);
        } catch (Exception ex) {
            throw new Exception("Method Table crawling failed.", ex);
        }

        // Annotate all frozen objects.
        try {
            var annotator = new FrozenObjectAnnotator(program, manager);
            annotator.analyze(directory, pointerScan.getPointerLocations(), monitor, log);
        }
        catch (Exception ex) {
            throw new Exception("Frozen object crawling failed.", ex);
        }
    }

    private ReadyToRunDirectory readRtrDirectory(Program program, Address moduleHeader) throws Exception {
        var listing = program.getListing();
        var symbolTable = program.getSymbolTable();

        // Read the rtr directory.
        var provider = new MemoryByteProvider(
            program.getMemory(),
            moduleHeader.getAddressSpace()
        );

        var reader = new BinaryReader(provider, true);
        reader.setPointerIndex(moduleHeader.getOffset());

        var directory = new ReadyToRunDirectory(reader);

        // Assign label and data type in listing.
        var type = directory.toDataType();
        listing.clearCodeUnits(moduleHeader, moduleHeader.add(type.getLength()), false);
        listing.createData(moduleHeader, type);
        symbolTable.createLabel(moduleHeader, Constants.READY_TO_RUN_HEADER_SYMBOL_NAME, SourceType.ANALYSIS);

        return directory;
    }

    private PointerScanResult rehydrateData(Program program, ReadyToRunSection rehydratedData, MetadataRehydrator rehydrator, TaskMonitor monitor, MessageLog log) throws Exception {
        var symbolTable = program.getSymbolTable();

        // Rehydrate.
        var space = program.getAddressFactory().getDefaultAddressSpace();
        var start = space.getAddress(rehydratedData.getStart());
        var end = space.getAddress(rehydratedData.getEnd());

        symbolTable.createLabel(start, Constants.DEHYDRATED_DATA_SYMBOL_NAME, SourceType.ANALYSIS);

        var result = rehydrator.rehydrate(program, new AddressSet(start, end).getFirstRange(), monitor, log);

        symbolTable.createLabel(
            result.getScanningRange().getMinAddress(),
            Constants.HYDRATED_DATA_SYMBOL_NAME,
            SourceType.ANALYSIS
        );

        return result;
    }

    private PointerScanResult scanForPointers(Program program, Address moduleHeader, TaskMonitor monitor, MessageLog log) throws CancelledException {
        var memory = program.getMemory();
        var validAddresses = memory.getLoadedAndInitializedAddressSet();
        var pointers = new java.util.ArrayList<Address>();

        var moduleBlock = memory.getBlock(moduleHeader);
        if (moduleBlock == null) {
            log.appendMsg(Constants.TAG, "Could not find memory block for module header at " + moduleHeader);
            return new PointerScanResult(new AddressRangeImpl(moduleHeader, moduleHeader), new Address[0]);
        }
        
        // We use the block containing the module header as the scanning range
        var scanningRange = new AddressRangeImpl(
            moduleBlock.getStart(), 
            moduleBlock.getEnd()
        );

        monitor.setMessage(Constants.TAG + ": Scanning for pointers...");
        monitor.setMaximum(moduleBlock.getSize());
        monitor.setProgress(0);

        var start = moduleBlock.getStart();
        var end = moduleBlock.getEnd();

        // Align start to 8 bytes
        long offset = start.getOffset();
        if (offset % 8 != 0) {
            start = start.add(8 - (offset % 8));
        }

        while (start.compareTo(end) <= 0) {
            monitor.checkCancelled();
            monitor.setProgress(start.getOffset() - moduleBlock.getStart().getOffset());
            
            // Read 64-bit value
            try {
                long value = memory.getLong(start);
                
                // Simple heuristic: If the value is an address that exists in memory, it's a candidate pointer.
                // This includes pointers to code (VTable slots) and pointers to data (RelatedType, Interfaces).
                if (validAddresses.contains(start.getNewAddress(value))) {
                    pointers.add(start);
                }
            } catch (MemoryAccessException e) {
                // Ignore read errors
            }
            
            try {
                start = start.add(8);
            } catch(AddressOutOfBoundsException e) {
                break; 
            }
        }
        
        log.appendMsg(Constants.TAG, "Found " + pointers.size() + " candidate pointers.");

        return new PointerScanResult(
            scanningRange,
            pointers.toArray(Address[]::new)
        );
    }
}
