//Crawls and annotates Method Tables in a NativeAOT compiled .NET program from a provided starting method table address.
//@author Washi (@washi_dev)
//@category NativeAOT
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.nio.charset.StandardCharsets;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.cmd.disassemble.*;
import ghidra.program.database.symbol.*;
import java.util.*;

public class NativeAotMethodTableAnalyzer extends GhidraScript {

    private static final CategoryPath CATEGORY_DOTNET   = new CategoryPath("/dotnet");
    private static final String       METHOD_TABLE_TYPE = "MT";

    private Stack<Candidate> _agenda = new Stack<>();
    private DataType _baseMethodTableType;

    public void run() throws Exception {
        var addressFactory = currentProgram.getAddressFactory();
        _baseMethodTableType = getBaseMethodTableType();

        var visited = new HashSet<Address>();
        _agenda.push(new Candidate(getStartAddress(), false));

        while (_agenda.size() > 0) {
            var current = _agenda.pop();

            // Is this a valid address?
            if (!visited.add(current.address) 
                || !addressFactory.isValidAddress(current.address)
                || current.address.getOffset() == 0) {
                continue;
            }

            // Read the method table at the current address.
            var mt = readMethodTable(current.address);

            // Process vtable entries.
            var methods = new ArrayList<Function>();
            for (var slot : mt.vtable)
                methods.add(getMethodFunction(current, slot));

            // Create new method table type and assign to method table in memory.
            var mtType = createMethodTableType(current, mt, methods);
            clearListing(current.address, current.address.add(mtType.getLength()));
            createData(current.address, mtType);

            // Recursively crawl all referenced types in the MT.
            _agenda.push(new Candidate(mt.baseType, false));
            for (var x : mt.interfaces)
                _agenda.push(new Candidate(x, true));
        }
    }

    private Address getStartAddress() throws Exception {
        // TODO: maybe autodetect
        return askAddress("Method Table Crawler", "Address of first MethodTable:");   
    }

    /**
     * Reads an address (pointer) at the provided address (analogous to getInt and getLong).
     */
    private Address getAddress(Address addr) throws Exception {
        return addr.getNewAddress(getLong(addr));
    }

    /**
     * Parses a single Method Table at the provided memory address.
     */
    private MethodTable readMethodTable(Address addr) throws Exception {
        var result = new MethodTable();

        // Read fixed fields.
        result.flags = getInt(addr);
        result.baseSize = getInt(addr.add(4));
        result.baseType = getAddress(addr.add(4 + 4));
        short vtableSlotCount = getShort(addr.add(4 + 4 + 8));
        short interfaceCount = getShort(addr.add(4 + 4 + 8 + 2));
        result.hashCode = getInt(addr.add(4 + 4 + 8 + 2 + 2));

        // Read vtable slots.
        var current = addr.add(4 + 4 + 8 + 2 + 2 + 4);
        for (int i = 0; i < vtableSlotCount; i++) {
            result.vtable.add(getAddress(current));
            current = current.add(8);
        }
        
        // Read interface slots.
        for (int i = 0; i < interfaceCount; i++) {
            result.interfaces.add(getAddress(current));
            current = current.add(8);
        }

        return result;
    }

    /**
     * Gets or creates the data type representing the header of every Method Table.
     */
    private DataType getBaseMethodTableType() {
        var manager = currentProgram.getDataTypeManager();
        var result = manager.getDataType(CATEGORY_DOTNET, METHOD_TABLE_TYPE);

        if (result == null) {
            var newType = new StructureDataType​(CATEGORY_DOTNET, METHOD_TABLE_TYPE, 0);

            newType.add(UnsignedIntegerDataType.dataType, 0, "Flags", null);
            newType.add(UnsignedIntegerDataType.dataType, 0, "BaseSize", null);
            newType.add(new PointerDataType(newType), 8, "BaseType", null);
            newType.add(ShortDataType.dataType, 0, "NumVtableSlots", null);
            newType.add(ShortDataType.dataType, 0, "NumInterfaces", null);
            newType.add(UnsignedIntegerDataType.dataType, 0, "HashCode", null);

            result = newType;
            manager.addDataType(result, DataTypeConflictHandler.DEFAULT_HANDLER);
        }

        return result;
    }

    /**
     * Gets or creates a function definition representing the method at the provided VTable slot.
     */
    private Function getMethodFunction(Candidate current, Address slot) throws Exception {
        var block = getMemoryBlock(slot);
        if (block == null)
            return null;

        if (block.isExecute()) {
            // This is a virtual function.
            var existing = getSymbolAt(slot);

            Function function = null;
            if (existing != null) {
                if (existing instanceof FunctionSymbol) {
                    function = getFunctionAt(slot);
                } else {
                    clearListing(slot);
                }
            }

            if (function == null)
                function = createFunction(slot, null);

            if (function.getName().startsWith("FUN_"))
                function.setName(String.format("Method_%s", slot), SourceType.ANALYSIS);

        } else if (!block.isWrite()) {
            // This is a nested method table chunk, we should explore this recursively.
            _agenda.push(new Candidate(getAddress(slot), current.isInterface));
        }

        return null;
    }

    /**
     * Constructs a new method table structure specific for the provided parsed method table.
     */
    private DataType createMethodTableType(
        Candidate candidate, 
        MethodTable mt,
        List<Function> methods)
        throws Exception 
    {
        var manager = currentProgram.getDataTypeManager();

        // Decide on a new name for the MT structure.
        String newTypeName;

        if (candidate.isInterface) {
            newTypeName = String.format("%s_InterfaceImpl_%s", METHOD_TABLE_TYPE, candidate.address);
        } if (mt.isLikelySystemObject()) {
            newTypeName = String.format("%s_Object", METHOD_TABLE_TYPE);
        } else {
            newTypeName = String.format("%s_Type_%s", METHOD_TABLE_TYPE, candidate.address);
        }

        // See if a type is already registered.
        var result = manager.getDataType(CATEGORY_DOTNET, newTypeName);
        
        if (result == null) {
            // Build up a new MT structure.
            var newType = new StructureDataType​(CATEGORY_DOTNET, newTypeName, 0);
            newType.add(_baseMethodTableType, 0, "MethodTable", null);

            for (int i = 0; i < mt.vtable.size(); i++) {
                // Try to use the method's signature as a type.
                var fieldType = methods.get(i) != null 
                    ? new PointerDataType(new FunctionDefinitionDataType​(methods.get(i), false))
                    : PointerDataType.dataType;

                newType.add(fieldType, 8, String.format("Method%d", i), null);
            }

            for (int i = 0; i < mt.interfaces.size(); i++) {
                newType.add(PointerDataType.dataType, 8, String.format("Interface%d", i), null);
            }
            
            result = newType;
            manager.addDataType(result, DataTypeConflictHandler.DEFAULT_HANDLER);
        }

        return result;
    }

    /**
     * Represents a single method table parsed from a NativeAOT binary.
     * Reference: https://github.com/dotnet/runtime/blob/7f42ffa3785dcb707f2ee9365f09e0058f21482d/src/coreclr/nativeaot/Runtime/inc/MethodTable.h
     */
    class MethodTable 
    {
        // Header fields (minus vtable and interface counts).
        public int flags;
        public int baseSize;
        public Address baseType;
        public int hashCode;

        // Parsed vtable and interface slots.
        public List<Address> vtable = new ArrayList<>();
        public List<Address> interfaces = new ArrayList<>();

        /**
         * Performs a basic heuristic that tests whether the MT is likely representing System.Object.
         */
        public boolean isLikelySystemObject() {
            return baseType.getOffset() == 0
                && vtable.size() == 3
                && interfaces.size() == 0
                && baseSize == 0x18;
        }
    }

    class Candidate {
        public Address address;
        public boolean isInterface;

        public Candidate(Address address, boolean isInterface) {
            this.address = address;
            this.isInterface = isInterface;
        }
    }
    

}