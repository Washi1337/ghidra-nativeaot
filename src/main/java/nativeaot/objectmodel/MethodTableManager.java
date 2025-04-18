
package nativeaot.objectmodel;

import java.io.FileWriter;
import java.util.HashMap;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

public abstract class MethodTableManager {

    private final HashMap<Long, MethodTable> _methodTables = new HashMap<>();
    private MethodTable _objectMT;
    private MethodTable _stringMT;
    private final Program _program;

    public MethodTableManager(Program program) {
        _program = program;
    }

    public Program getProgram() {
        return _program;
    }

    public int getMethodTableCount() {
        return _methodTables.size();
    }

    public Iterable<MethodTable> getMethodTables() {
        return _methodTables.values();
    }

    public MethodTable getMethodTable(Address address) {
        return getMethodTable(address.getOffset());
    }

    public MethodTable getMethodTable(long address) {
        return _methodTables.getOrDefault(address, null);
    }

    public MethodTable getMethodTable(GhidraClass clazz) {
        for (var mt : _methodTables.values()) {
            if (mt.getGhidraClass() == clazz) {
                return mt;
            }
        }
        return null;
    }

    public MethodTable getObjectMT() {
        return _objectMT;
    }

    public void setObjectMT(MethodTable objectMT) {
        assertIsRegistered(objectMT);
        _objectMT = objectMT;
    }

    public MethodTable getStringMT() {
        return _stringMT;
    }

    public void setStringMT(MethodTable stringMT) {
        assertIsRegistered(stringMT);
        _stringMT = stringMT;
    }

    public abstract MethodTable createMT(Address address);

    public void registerMT(MethodTable table) {
        _methodTables.put(table.getAddress().getOffset(), table);
    }

    public abstract void restoreFromDB();

    public void clear() {
        _methodTables.clear();
    }

    private void assertIsRegistered(MethodTable mt) {
        var existing = getMethodTable(mt.getAddress());
        if (existing == null || existing != mt) {
            throw new IllegalArgumentException(String.format("%s is not registered as a method table.", mt));
        }
    }

    private void dumpMTs(TaskMonitor monitor) throws Exception {
        try (var writer = new FileWriter("/tmp/output.txt")) {
            for (var mt: getMethodTables()) {
                writer.write(mt.getAddress().toString());
                writer.write(": ");
                for (var symbol: _program.getSymbolTable().getSymbols(mt.getAddress())) {
                    writer.write(symbol.getName());
                    writer.write(" ");
                }
                writer.write("\n");
            }
        }
    }

    public GhidraClass getOrCreateGhidraClass(MethodTable mt, String originalName) throws Exception {
        var symbolTable = _program.getSymbolTable();

        var ns = symbolTable.getOrCreateNameSpace(
            _program.getGlobalNamespace(),
            originalName == null ? getNewMTName(mt) : originalName,
            SourceType.ANALYSIS
        );

        if (ns instanceof GhidraClass c) {
            return c;
        } else {
            return symbolTable.convertNamespaceToClass(ns);
        }
    }

    private String getNewMTName(MethodTable table) {
        return switch (table.getElementType()) {
            case ElementType.CLASS -> String.format("Class_%s", table.getAddress());
            case ElementType.VALUETYPE -> String.format("Struct_%s", table.getAddress());
            case ElementType.NULLABLE -> String.format("Nullable_%s", table.getAddress());
            case ElementType.INTERFACE -> String.format("IInterface_%s", table.getAddress());
            case ElementType.ARRAY -> String.format("Array_%s", table.getAddress());
            case ElementType.SZARRAY -> String.format("SzArray_%s", table.getAddress());
            case ElementType.BOOLEAN -> String.format("Enum_Boolean_%s", table.getAddress());
            case ElementType.CHAR -> String.format("Enum_Char_%s", table.getAddress());
            case ElementType.SBYTE -> String.format("Enum_Sbyte_%s", table.getAddress());
            case ElementType.BYTE -> String.format("Enum_Byte_%s", table.getAddress());
            case ElementType.INT16 -> String.format("Enum_Int16_%s", table.getAddress());
            case ElementType.UINT16 -> String.format("Enum_Uint16_%s", table.getAddress());
            case ElementType.INT32 -> String.format("Enum_Int32_%s", table.getAddress());
            case ElementType.UINT32 -> String.format("Enum_Uint32_%s", table.getAddress());
            case ElementType.INT64 -> String.format("Enum_Int64_%s", table.getAddress());
            case ElementType.UINT64 -> String.format("Enum_Uint64_%s", table.getAddress());
            case ElementType.INTPTR -> String.format("Enum_IntPtr_%s", table.getAddress());
            case ElementType.UINTPTR -> String.format("Enum_UIntPtr_%s", table.getAddress());
            case ElementType.SINGLE -> String.format("Enum_Single_%s", table.getAddress());
            case ElementType.DOUBLE -> String.format("Enum_Double_%s", table.getAddress());
            default -> String.format("Type_%s", table.getAddress());
        };
    }    
}