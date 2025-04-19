package nativeaot.objectmodel;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import nativeaot.Constants;
import nativeaot.rtr.ReadyToRunDirectory;
import nativeaot.rtr.ReadyToRunSection;

public class FrozenObjectAnnotator {
    private static final int STRING_LENGTH_FIELD_OFFSET = 8;
    private static final int ARRAY_LENGTH_FIELD_OFFSET = 8;
    private static final int MAX_STRING_LENGTH = 0x1_0000;
    private static final int MAX_ARRAY_LENGTH = 0x1_0000;

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

    private int annotateObjects(ReadyToRunSection section, Address[] pointerLocations, TaskMonitor monitor) {
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
            // TODO: Array values.
            
            if (mt.getAddress().getOffset() == _manager.getStringMT().getAddress().getOffset()) {
                success = annotateString(location);
            } else if (mt.isSzArray()) {
                success = annotateSzArray(location, mt);
            } else if (mt.isClass() || mt.isValueType()) {
                success = annotateObject(location, mt);
            }
            
            if (success) {
                count += 1;
            }
        }
        return count;
    }

    private boolean annotateString(Address location) {
        try {
            var instanceType = _manager.getStringMT().getOrCreateInstanceType();

            var memory = _program.getMemory();
            var listing = _program.getListing();
            var symbolTable = _program.getSymbolTable();

            // Check if the length makes any sense.
            int length = memory.getInt(location.add(STRING_LENGTH_FIELD_OFFSET));
            if (length < 0 || length >= MAX_STRING_LENGTH) {
                throw new Exception("String size %d exceeded max size %d".formatted(length, MAX_STRING_LENGTH));
            }

            // Verify there is a zero-terminator.
            var stringStart = location.add(instanceType.getLength());
            var stringEnd = stringStart.add(length * 2);
            if (memory.getByte(stringEnd) != 0) {
                throw new Exception("No zero-terminator found at supposed string end %s".formatted(stringEnd));
            }

            // Replace any annotations with the string annotation.
            listing.clearCodeUnits(location, stringEnd, true);
            listing.createData(location, instanceType);

            String literalName = length > 0
                ? listing.createData(location.add(instanceType.getLength()), TerminatedUnicodeDataType.dataType).getPathName()
                : "String_Empty_%s".formatted(location);

            symbolTable.createLabel(location, "dn_%s".formatted(literalName), SourceType.ANALYSIS);

            return true;
        } catch (Exception ex) {
            Msg.error(Constants.TAG, "Failed to create string literal at %s".formatted(location), ex);
            return false;
        }
    }

    private boolean annotateSzArray(Address location, MethodTable mt) {
        var elementType = mt.getRelatedType();
        if (elementType == null) {
            return false;
        }

        try {
            var instanceType = mt.getOrCreateInstanceType();

            var memory = _program.getMemory();
            var listing = _program.getListing();

            // Check if the length makes any sense.
            int length = memory.getInt(location.add(ARRAY_LENGTH_FIELD_OFFSET));
            if (length < 0 || length >= MAX_ARRAY_LENGTH) {
                throw new Exception("Array size %d exceeded max size %d".formatted(length, MAX_ARRAY_LENGTH));
            }

            var dataStart = location.add(instanceType.getLength());

            // Replace object header.
            listing.clearCodeUnits(location, dataStart, true);
            listing.createData(location, instanceType);

            // Set array data.
            if (length > 0) {
                // Determine element type to use for the inline array.
                var elementInstanceType = switch (elementType.getElementType()) {
                    case ElementType.BOOLEAN -> BooleanDataType.dataType;
                    case ElementType.CHAR -> WideChar16DataType .dataType;
                    case ElementType.SBYTE -> SignedByteDataType.dataType;
                    case ElementType.BYTE -> ByteDataType.dataType;
                    case ElementType.INT16 -> ShortDataType.dataType;
                    case ElementType.UINT16 -> UnsignedShortDataType.dataType;
                    case ElementType.INT32 -> IntegerDataType.dataType;
                    case ElementType.UINT32 -> UnsignedIntegerDataType.dataType;
                    case ElementType.INT64 -> LongLongDataType.dataType;
                    case ElementType.UINT64 -> UnsignedLongLongDataType.dataType;
                    case ElementType.INTPTR, ElementType.UINTPTR -> Pointer64DataType.dataType; // TODO: use program pointer type
                    case ElementType.SINGLE -> FloatDataType.dataType;
                    case ElementType.DOUBLE -> DoubleDataType.dataType;
                    case ElementType.VALUETYPE -> throw new UnsupportedOperationException("Struct arrays not supported yet.");
                    default -> elementType.getOrCreateInstanceType();
                };

                listing.createData(dataStart, new ArrayDataType(elementInstanceType, length));
            }

            return true;
        } catch (Exception ex) {
            Msg.error(Constants.TAG, "Failed to create SZ array at %s of type %s".formatted(location, mt), ex);
            return false;
        }
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