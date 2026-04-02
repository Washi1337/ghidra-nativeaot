package nativeaot.objectmodel.net70;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.Pointer64DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import nativeaot.Constants;
import nativeaot.objectmodel.ElementType;
import nativeaot.objectmodel.MethodTable;

import static ghidra.app.util.bin.StructConverter.DWORD;
import static ghidra.app.util.bin.StructConverter.WORD;

public class MethodTableNet70 extends MethodTable {
    private static final int ELEMENT_TYPE_MASK = 0xf800;
    private static final int ELEMENT_TYPE_SHIFT = 11;

    private short _componentSize;
    private short _flags;
    private int _baseSize;
    private long _relatedTypeAddress;
    private int _hashCode;
    private long[] _vtable;
    private long[] _interfaceSlots;

    public MethodTableNet70(MethodTableManagerNet70 manager, Address address) {
        super(manager, address);
    }

    public short getComponentSize() {
        return _componentSize;
    }

    public short getFlags() {
        return _flags;
    }

    @Override
    public int getElementType() {
        return (_flags & ELEMENT_TYPE_MASK) >>> ELEMENT_TYPE_SHIFT;
    }

    @Override
    public int getBaseSize() {
        return _baseSize;
    }

    @Override
    public int getDataSize() {
        return _baseSize
            - 0x8 /* obj header */
            - 0x8 /* mt */;
    }

    @Override
    public long getRelatedTypeAddress() {
        return _relatedTypeAddress;
    }

    @Override
    public long[] getVTable() {
        return _vtable;
    }

    @Override
    public int getVTableSlotCount() {
        return _vtable.length;
    }

    @Override
    public long getVTableSlot(int index) {
        return _vtable[index];
    }

    @Override
    public long[] getInterfaceAddresses() {
        return _interfaceSlots;
    }

    @Override
    protected Structure constructMTType() throws Exception {
        var result = new StructureDataType(getMTName(), 0);
        result.setCategoryPath(Constants.CATEGORY_METHOD_TABLES);
        result.setDescription(getAddress().toString());

        // https://github.com/dotnet/runtime/blob/b2dc37ba181a7fa4427e717eab819ba3543d0ae4/src/coreclr/nativeaot/Runtime/inc/MethodTable.h#L136-L142
        result.add(WORD, "m_usComponentSize", null);
        result.add(WORD, "uFlags", null);
        result.add(DWORD, "uBaseSize", null);
        result.add(Pointer64DataType.dataType, "relatedType", null);
        result.add(WORD, "usNumVtableSlots", null);
        result.add(WORD, "usNumInterfaces", null);
        result.add(DWORD, "uHashCode", null);

        int count = 0;
        for (var chunk : getVTableChunks()) {
            result.add(chunk.getOrCreateDataType(), String.format(VTABLE_MEMBER_FORMAT, count++), null);
        }

        if (_interfaceSlots.length > 0) {
            result.add(new ArrayDataType(Pointer64DataType.dataType, _interfaceSlots.length), "Interfaces", null);
        }

        return result;
    }

    @Override
    public void initFromMemory() throws Exception {
        var address = getAddress();

        var reader = new BinaryReader(
                new MemoryByteProvider(
                        getManager().getProgram().getMemory(),
                        address.getAddressSpace()
                ),
                true
        );
        reader.setPointerIndex(address.getOffset());

        _componentSize = reader.readNextShort();
        _flags = reader.readNextShort();
        _baseSize = reader.readNextInt();
        _relatedTypeAddress = reader.readNextLong();
        int vtableSlotCount = reader.readNextShort();
        int interfacesCount = reader.readNextShort();
        _hashCode = reader.readNextInt();

        if (vtableSlotCount < 0 || vtableSlotCount >= 1000)
            throw new IllegalArgumentException("Invalid VTable slot count");
        if (interfacesCount < 0 || interfacesCount >= 1000)
            throw new IllegalArgumentException("Invalid interface count");

        _vtable = new long[vtableSlotCount];
        for (int i = 0; i < vtableSlotCount; i++) {
            _vtable[i] = reader.readNextLong();
        }

        _interfaceSlots = new long[interfacesCount];
        for (int i = 0; i < interfacesCount; i++) {
            _interfaceSlots[i] = reader.readNextLong();
        }

        // Do some validation to see if the MT makes sense.
        var elementType = getElementType();
        if (elementType == ElementType.INTERFACE) {
            if (_baseSize != 0x00) {
                throw new Exception("Unexpected non-zero interface base size.");
            } else if (getRelatedTypeAddress() != 0) {
                throw new Exception("Unexpected non-zero interface related type.");
            }
        } else if (_baseSize < 0x10) { // TODO: abstract away
            throw new Exception("Unexpected base size.");
        }
    }
}
