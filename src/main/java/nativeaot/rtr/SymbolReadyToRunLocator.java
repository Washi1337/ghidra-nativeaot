
package nativeaot.rtr;

import java.lang.Exception;
import java.util.ArrayList;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;
import nativeaot.Constants;

public class SymbolReadyToRunLocator implements ReadyToRunLocator {

    @Override
    public Address[] locateModules(Program program, TaskMonitor monitor, MessageLog log) {
        var memory = program.getMemory();
        try {
            var candidates = findCandidates(program, monitor);
            for (int i = 0; i < candidates.size(); i++) {
                monitor.checkCancelled();
                try {
                    int signature = memory.getInt(candidates.get(i));
                    if (signature != Constants.READY_TO_RUN_SIGNATURE) {
                        candidates.remove(i);
                        i--;
                    }
                } catch (MemoryAccessException ignored) {
                }
            }
            return candidates.toArray(Address[]::new);
        } catch (Exception ex) {
            log.appendMsg("Failed to locate RTR roots using symbols.");
            log.appendException(ex);
            return new Address[0];
        }        
    }

    private ArrayList<Address> findCandidates(Program program, TaskMonitor monitor) throws Exception {
        var memory = program.getMemory();
        var symbolTable = program.getSymbolTable();

        var candidates = new ArrayList<Address>();

        // Try finding an already annotated RTR directory header.
        var directorySymbols = symbolTable.getSymbols(Constants.READY_TO_RUN_HEADER_SYMBOL_NAME);
        for (var symbol : directorySymbols) {
            candidates.add(symbol.getAddress());
        }

        // Try finding an already annotated RTR modules array.
        var modulesStartSymbol = symbolTable.getSymbols(Constants.READY_TO_RUN_MODULES_START_SYMBOL_NAME);
        if (!modulesStartSymbol.hasNext()) {
            return candidates;
        }

        var modulesEndSymbol = symbolTable.getSymbols(Constants.READY_TO_RUN_MODULES_END_SYMBOL_NAME);
        if (!modulesStartSymbol.hasNext()) {
            return candidates;
        }

        // Read all module header pointers in array.
        var start = modulesStartSymbol.next().getAddress();
        var end = modulesEndSymbol.next().getAddress();
        int count = (int) ((end.getOffset() - start.getOffset()) / 8);

        for (int i = 0; i < count; i++) {
            monitor.checkCancelled();
            try {
                long raw = memory.getLong(start.add(i * 8L));
                if (raw == 0) {
                    continue;
                }

                var address = start.getNewAddress(raw);
                if (!candidates.contains(address)) {
                    candidates.add(address);
                }
            } catch (MemoryAccessException ignored) {
            }
        }

        return candidates;
    }


}