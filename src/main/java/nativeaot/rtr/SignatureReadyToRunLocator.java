package nativeaot.rtr;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import nativeaot.Constants;

import java.util.ArrayList;

public class SignatureReadyToRunLocator implements ReadyToRunLocator {
    private static final byte EXPECTED_ENTRY_SIZE = 0x18;
    private static final byte EXPECTED_ENTRY_TYPE = 0x01;
    private static final byte EXPECTED_NUMBER_OF_SECTIONS_UPPER_BOUND = 0x50;

    @Override
    public Address[] locateModules(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException {
        var result = new ArrayList<Address>();
        var memory = program.getMemory();

        monitor.setMessage(Constants.TAG + ": Scanning for RTR signatures...");
        monitor.setMaximum(memory.getSize());
        monitor.setIndeterminate(false);
        monitor.setProgress(0);

        for (var block : memory.getBlocks()) {
            // We assume the modules are stored in an initialized data section.
            if (!block.isRead() || !block.isInitialized() || block.isExecute()) {
                continue;
            }

            var current = block.getStart();
            var end = block.getEnd();

            // Align start to 8 bytes
            long offset = current.getOffset();
            if (offset % 8 != 0) {
                current = current.add(8 - (offset % 8));
            }

            try{
                while (current.compareTo(end) <= 0) {
                    monitor.checkCancelled();
                    monitor.setProgress(current.getOffset() - block.getStart().getOffset());

                    if (isLikelyValidRtrHeader(memory, current)) {
                        result.add(current);
                    }

                    current = current.add(8);
                }
            } catch (MemoryAccessException e) {
                continue;
            }
        }

        return  result.toArray(new Address[0]);
    }

    private static boolean isLikelyValidRtrHeader(Memory memory, Address address) throws MemoryAccessException {
        // Expected pattern:
        // dOff     Type      Expected Value          Description
        // +0x00    ddw       00525452h               Signature
        // +0x04    dw        ??                      MajorVersion
        // +0x06    dw        ??                      MinorVersion
        // +0x08    ddw       ??                      Flags
        // +0x0c    dw        < 50h                   NumberOfSections
        // +0x0e    db        18h                     EntrySize
        // +0x0f    db        1h                      EntryType

        return memory.getInt(address) == Constants.READY_TO_RUN_SIGNATURE
                && memory.getByte(address.add(0x0C)) < EXPECTED_NUMBER_OF_SECTIONS_UPPER_BOUND
                && memory.getByte(address.add(0x0E)) == EXPECTED_ENTRY_SIZE
                && memory.getByte(address.add(0x0F)) == EXPECTED_ENTRY_TYPE;
    }
}
