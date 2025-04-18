
package nativeaot.rtr;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;

public class ReadyToRunSection {
    public static final int FROZEN_OBJECT_REGION = 206;
    public static final int DEHYDRATED_DATA = 207;

    private final int _type;
    private final int _flags;
    private final long _start;
    private final long _end;

    public ReadyToRunSection(BinaryReader reader) throws IOException {
        _type = reader.readNextInt();
        _flags = reader.readNextInt();
        _start = reader.readNextLong();
        _end = reader.readNextLong();
    }

    public int getType() {
        return _type;
    }

    public int getFlags() {
        return _flags;
    }

    public long getStart() {
        return _start;
    }

    public long getEnd() {
        return _end;
    }

    public Address[] getPointersInSection(Address[] addresses) {
        var result = new ArrayList<Address>();
        for (var address : addresses) {
            if (address.getOffset() >= getStart()
                && address.getOffset() < getEnd()) {
                result.add(address);
            }
        }
        return result.toArray(Address[]::new);
    }
}