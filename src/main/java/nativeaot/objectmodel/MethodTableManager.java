
package nativeaot.objectmodel;

import java.io.FileWriter;
import java.util.HashMap;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import nativeaot.Constants;
import nativeaot.objectmodel.net70.MethodTableManagerNet70;
import nativeaot.objectmodel.net80.MethodTableManagerNet80;
import nativeaot.rehydration.PointerScanResult;
import nativeaot.rtr.ReadyToRunDirectory;

public abstract class MethodTableManager {

    private final HashMap<Long, MethodTable> _methodTables = new HashMap<>();
    private MethodTable _objectMT;
    private MethodTable _stringMT;
    private final Program _program;

    public MethodTableManager(Program program) {
        _program = program;
    }

    public static MethodTableManager createForDirectory(Program program, ReadyToRunDirectory directory) {
        // NOTE: Method table managers should be changed if the file format changes per RTR version.

        if (directory.getMajorVersion() <= 0x08) {
            return new MethodTableManagerNet70(program);
        }

        return new MethodTableManagerNet80(program);
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

    protected boolean isLikelyCodePointer(PointerScanResult pointerScan, long value) {
        if (value == 0) {
            return true;
        }

        var candidateAddress = pointerScan.getScanningRange().getMinAddress().getNewAddress(value);
        var block = _program.getMemory().getBlock(candidateAddress);
        return block != null && block.isExecute();
    }

    protected abstract Address[] findCandidateSystemObjectMTs(PointerScanResult pointerScan, TaskMonitor monitor) throws Exception;

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

    public void restoreFromDB() {
        clear();

        var dataTypeManager = getProgram().getDataTypeManager();
        var space = getProgram().getAddressFactory().getDefaultAddressSpace();
        var naotCategory = dataTypeManager.getCategory(Constants.CATEGORY_NATIVEAOT);
        var mtCategory = dataTypeManager.getCategory(Constants.CATEGORY_METHOD_TABLES);

        if (naotCategory == null || mtCategory == null) {
            return;
        }

        // Restore all MT types and addresses from DT manager.
        for (var mtType: mtCategory.getDataTypes()) {
            if (!mtType.getName().endsWith("_MT")) {
                continue;
            }
            var name = mtType.getName().substring(0, mtType.getName().length() - 3);

            Address address;
            try {
                address = space.getAddress(mtType.getDescription());
            } catch (Exception ex) {
                continue;
            }

            var mt = createMT(address);
            try {
                mt.initFromMemory();
                mt.setGhidraClass(getOrCreateGhidraClass(mt, name));
            } catch (Exception ex) {
                continue;
            }

            registerMT(mt);

            switch (name) {
                case Constants.SYSTEM_OBJECT_NAME -> setObjectMT(mt);
                case Constants.SYSTEM_STRING_NAME -> setStringMT(mt);
            }
        }

        // Rebuild type inheritance graph.
        for (var mt : getMethodTables()) {
            mt.setRelatedType(getMethodTable(mt.getRelatedTypeAddress()));

            mt.getInterfaces().clear();
            for (var iface: mt.getInterfaceAddresses()) {
                if (iface == 0) {
                    continue;
                }

                var interfaceMT = getMethodTable(iface);
                if (interfaceMT == null) {
                    continue;
                }

                mt.getInterfaces().add(interfaceMT);
            }
        }

        // Link all MTs to the database.
        for (var mt : getMethodTables()) {
            try {
                mt.commitToDB();
            } catch (Exception e) {
                Msg.error(Constants.TAG, "Failed to commit %s".formatted(mt), e);
            }
        }
    }

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