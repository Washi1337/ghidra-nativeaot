package nativeaot.objectmodel;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.TerminatedUnicodeDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import nativeaot.Constants;
import nativeaot.rtr.ReadyToRunDirectory;
import nativeaot.rtr.ReadyToRunSection;

public class FrozenObjectAnnotator {
    private static final int MAX_STRING_LENGTH = 0x1_0000;

    private final Program _program;
    private final MethodTableManager _manager;

    public FrozenObjectAnnotator(Program program, MethodTableManager manager) {
        _program = program;
        _manager = manager;
    }

    public void analyze(ReadyToRunDirectory directory, Address[] pointerLocations, TaskMonitor monitor, MessageLog log) throws Exception {
        var section = directory.getSectionByType(ReadyToRunSection.FROZEN_OBJECT_REGION);
        if (section == null) {
            log.appendMsg(Constants.TAG, "No frozen object section present in ReadyToRun directory.");
            return;
        }

        var sectionStart = pointerLocations[0].getNewAddress(section.getStart());
        ensureSymbolAdded(sectionStart);

        int count = annotateObjects(section, pointerLocations, monitor);

        log.appendMsg(Constants.TAG, String.format("Found %d objects", count));
    }

    private void ensureSymbolAdded(Address sectionStart) throws InvalidInputException {
        var symbolTable = _program.getSymbolTable();
        var symbols = symbolTable.getSymbols(sectionStart);
        
        boolean hasSymbol = false;
        for (int i = 0; i < symbols.length && !hasSymbol; i++) {
            if (symbols[i].getName().equals(Constants.FROZEN_SEGMENT_START_SYMBOL_NAME)) {
                hasSymbol = true;
            }
        }
        
        if (!hasSymbol) {
            symbolTable.createLabel(sectionStart, Constants.FROZEN_SEGMENT_START_SYMBOL_NAME, SourceType.ANALYSIS);
        }
    }

    private int annotateObjects(ReadyToRunSection section, Address[] pointerLocations, TaskMonitor monitor) throws Exception {
        var pointersInSection = section.getPointersInSection(pointerLocations);
        monitor.setIndeterminate(false);
        monitor.setProgress(0);
        monitor.setMaximum(pointersInSection.length);
        monitor.setMessage(String.format("%s: Finding frozen objects", Constants.TAG));
        int count = 0;
        for (int i = 0; i < pointersInSection.length; i++) {
            monitor.setProgress(i);
            var location = pointersInSection[i];
            
            // Read the pointer at the reference.
            long dereferenced;
            try {
                dereferenced = _program.getMemory().getLong(location);
            } catch (MemoryAccessException ex) {
                // Broken reference, ignore.
                continue;
            }
            
            // Check if the pointer is referencing a MT.
            var mt = _manager.getMethodTable(dereferenced);
            if (mt == null) {
                continue;
            }
            
            boolean success = false;
            
            // Annotate object.
            // TODO: Array and SzArray values.
            
            if (mt.getAddress() == _manager.getStringMT().getAddress()) {
                success = annotateString(location);
            } else if (mt.getElementType() == ElementType.CLASS || mt.getElementType() == ElementType.VALUETYPE) {
                success = annotateObject(location, mt);
            }
            
            if (success) {
                count += 1;
            }
        }
        return count;
    }

    private boolean annotateString(Address location) throws Exception {
        var instanceType = _manager.getStringMT().getOrCreateInstanceType();

        var memory = _program.getMemory();
        var listing = _program.getListing();
        var symbolTable = _program.getSymbolTable();

        // Check if the length makes any sense.
        var length = memory.getInt(location.add(8));
        if (length <= 0 || length >= MAX_STRING_LENGTH) {
            return false;
        }

        // Verify there is a zero-terminator.
        var stringStart = location.add(instanceType.getLength());
        var stringEnd = stringStart.add(length * 2);
        if (memory.getByte(stringEnd) != 0) {
            return false;
        }

        // Replace any annotations with the string annotation.
        listing.clearCodeUnits(location, stringEnd, true);
        listing.createData(location, instanceType);
        var literal = listing.createData(location.add(instanceType.getLength()), TerminatedUnicodeDataType.dataType);
        var name = "dn_" + literal.getPathName();
        symbolTable.createLabel(location, name, SourceType.ANALYSIS);
        return true;
    }

    private boolean annotateObject(Address location, MethodTable mt) {
        try {
            _program.getListing().createData(location, mt.getOrCreateInstanceType());
            return true;
        } catch (Exception ex) {
            return false;
        }
    }
}