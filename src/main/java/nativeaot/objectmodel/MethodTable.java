package nativeaot.objectmodel;

import java.lang.Exception;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import nativeaot.Constants;

public abstract class MethodTable {

    public static final String METHOD_TABLE_FORMAT = "%s_MT";
    public static final String VTABLE_TABLE_FORMAT = "%s_vtbl";
    public static final String VTABLE_MEMBER_PREFIX = "vtbl_";
    public static final String VTABLE_MEMBER_FORMAT = "vtbl_%d";
    public static final String VTABLE_SYMBOL_NAME = "`vftable'";

    private final MethodTableManager _manager;
    private final Address _address;

    private GhidraClass _class;
    private Symbol _mtSymbol;
    private Data _mtData;
    private ArrayList<VTableChunk> _vtableChunks;
    private VTableChunk _ownChunk;

    private MethodTable _relatedType;
    private final List<MethodTable> _interfaces = new ArrayList<>();

    private final HashSet<MethodTable> _derivedTypes = new HashSet<>();

    public MethodTable(MethodTableManager manager, Address address) {
        _manager = manager;
        _address = address;
    }

    protected void assertHasClass() throws Exception {
        if (_class == null) {
            throw new Exception("Method table %s is not attached to a class.".formatted(_address));
        }
    }

    public MethodTableManager getManager() {
        return _manager;
    }

    public Address getAddress() {
        return _address;
    }

    public String getName() {
        return _class != null 
            ? _class.getName()
            : "Class_%s".formatted(_address);
    }

    public void setName(String name) throws Exception {
        assertHasClass();

        getOrCreateMTType().setName(getMTName(name));
        getOrCreateInstanceType().setName(name);

        if (_ownChunk != null) {
            _ownChunk.propagateNameChange(name);
        }

        _class.getSymbol().setName(name, SourceType.ANALYSIS);
    }

    public abstract int getElementType();

    public boolean isClass() {
        return getElementType() == ElementType.CLASS;
    }

    public boolean isStruct() {
        return getElementType() == ElementType.VALUETYPE;
    }

    public boolean isInterface() {
        return getElementType() == ElementType.INTERFACE;
    }

    public boolean isSzArray() {
        return getElementType() == ElementType.SZARRAY;
    }

    public boolean isValueType() {
        return ElementType.isValueType(getElementType());
    }

    public boolean isArrayInstance() {
        return ElementType.isArrayInstance(getElementType());
    }

    public abstract int getBaseSize();

    public abstract int getDataSize();

    public abstract long getRelatedTypeAddress();

    public MethodTable getRelatedType() {
        return _relatedType;
    }

    public void setRelatedType(MethodTable relatedType) {
        if (_relatedType != null) {
            _relatedType.removeDerivedType(this);
        }

        _relatedType = relatedType;

        if (relatedType != null) {
            relatedType.addDerivedType(this);
        }
    }

    public Symbol getMTSymbol() {
        return _mtSymbol;
    }

    public void setMTSymbol(Symbol mtSymbol) {
        _mtSymbol = mtSymbol;
    }

    public Data getMTData() {
        return _mtData;
    }

    public void setMTData(Data mtData) {
        _mtData = mtData;
    }

    public abstract long[] getVTable();

    public abstract int getVTableSlotCount();

    public abstract long getVTableSlot(int index);

    public Method getMethod(int slotIndex) {
        for (var chunk : getVTableChunks()) {
            if (slotIndex >= chunk.getBaseIndex() && slotIndex < chunk.getBaseIndex() + chunk.size()) {
                return chunk.getMethod(slotIndex - chunk.getBaseIndex());
            }
        }

        return null;
    }

    public abstract long[] getInterfaceAddresses();

    public List<MethodTable> getInterfaces() {
        return _interfaces;
    }

    protected void addDerivedType(MethodTable table) {
        _derivedTypes.add(table);
    }

    protected void removeDerivedType(MethodTable table) {
        _derivedTypes.remove(table);
    }

    public Iterable<MethodTable> getDerivedTypes() {
        return _derivedTypes;
    }

    protected abstract Structure constructMTType() throws Exception;

    protected String getMTName() {
        return getMTName(getName());
    }

    public static String getMTName(String name) {
        return String.format(METHOD_TABLE_FORMAT, name);
    }

    public DataType getMTType() throws Exception {
        assertHasClass();

        return _manager.getProgram()
            .getDataTypeManager()
            .getDataType(Constants.CATEGORY_METHOD_TABLES, getMTName());
    }

    public DataType getOrCreateMTType() throws Exception {
        assertHasClass();
        var mtType = getMTType();

        if(!(mtType instanceof Structure)) {
            var program = _manager.getProgram();
            var dtManager = program.getDataTypeManager();

            mtType = program.withTransaction("Create MT type for %s".formatted(getName()), () -> {
                return dtManager.addDataType(
                    constructMTType(),
                    DataTypeConflictHandler.KEEP_HANDLER
                );
            });
        }

        return mtType;
    }

    protected abstract Structure constructInstanceType() throws Exception;

    public Structure getInstanceType() throws Exception {
        assertHasClass();

        return (Structure) _manager.getProgram()
            .getDataTypeManager()
            .getDataType(Constants.CATEGORY_NATIVEAOT, getName());
    }

    public Structure getOrCreateInstanceType() throws Exception {
        assertHasClass();
        var instanceType = getInstanceType();

        if (instanceType == null) {
            var program = _manager.getProgram();
            var dtManager = program.getDataTypeManager();

            instanceType = program.withTransaction("Create instance type for %s".formatted(getName()), () -> {
                return (Structure) dtManager.addDataType(
                    constructInstanceType(),
                    DataTypeConflictHandler.KEEP_HANDLER
                );
            });
        }

        return instanceType;
    }

    public VTableChunk getOwnVTableChunk() {
        // Ensure chunks are created.
        getVTableChunks();

        return _ownChunk;
    }

    public Iterable<VTableChunk> getVTableChunks() {
        if (_vtableChunks != null) {
            return _vtableChunks;
        }

        var result = new ArrayList<VTableChunk>();

        // If no slots, then there is nothing to do.
        var vtable = getVTable();
        if (vtable.length == 0) {
            return result;
        }

        // Determine direct parent type.
        MethodTable baseType;
        if (isArrayInstance()) {
            // TODO: use System.Array base mt instead.
            baseType = _manager.getObjectMT();
        } else {
            baseType = getRelatedType();
        }

        // Embed all vtables of the parent type.
        int inheritedCount = 0;
        if (baseType != null) {
            for (var chunk : baseType.getVTableChunks()) {
                result.add(chunk);
                inheritedCount += chunk.size();

                if (inheritedCount >= vtable.length) {
                    break;
                }
            }
        }

        // Bunch remainder together into a new vtable chunk.
        if (inheritedCount < vtable.length) {
            int remainder = vtable.length - inheritedCount;
            _ownChunk = new VTableChunk(this, inheritedCount, remainder);
            result.add(_ownChunk);
        }

        _vtableChunks = result;
        return result;
    }

    public GhidraClass getGhidraClass() {
        return _class;
    }

    public void setGhidraClass(GhidraClass clazz) {
        _class = clazz;
    }

    public abstract void commitToDB() throws Exception;

    public abstract void initFromMemory() throws Exception;

    @Override
    public String toString() {
        return String.format("%s (%s)", _address, getName());
    }
}
