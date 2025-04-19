
package nativeaot.rtr;

import java.io.IOException;
import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer64DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import nativeaot.Constants;


public class ReadyToRunDirectory implements StructConverter {

    private final short _majorVersion;
    private final short _minorVersion;
    private final int _attributes;
    private final ReadyToRunSection[] _sections;

    public ReadyToRunDirectory(BinaryReader reader) throws IOException {
        if (reader.readNextInt() != Constants.READY_TO_RUN_SIGNATURE) {
            throw new IOException("Reader does not start with the magic RTR\0");
        }
        _majorVersion = reader.readNextShort();
        _minorVersion = reader.readNextShort();
        _attributes = reader.readNextInt();

        short sectionCount = reader.readNextShort();
        byte entrySize = reader.readNextByte();
        byte entryType = reader.readNextByte();

        if (sectionCount > 100) {
            throw new IOException("Unexpected number of sections $d".formatted(sectionCount));
        }

        _sections = new ReadyToRunSection[sectionCount];
        for (int i = 0; i < sectionCount; i++) {
            _sections[i] = new ReadyToRunSection(reader);
        }
    }

    public ReadyToRunSection[] getSections() {
        return Arrays.copyOf(_sections, _sections.length);
    }

    public ReadyToRunSection getSectionByType(int type) {
        for (var section : _sections) {
            if (section.getType() == type) {
                return section;
            }
        }

        return null;
    }

    public short getMajorVersion() {
        return _majorVersion;
    }

    public short getMinorVersion() {
        return _minorVersion;
    }

    public int getAttributes() {
        return _attributes;
    }

    public int getSectionCount() {
        return _sections.length;
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        var row = new StructureDataType("ModuleInfoRow", 0);
        row.add(DWORD, "Type", null);
        row.add(DWORD, "Flags", null);
        row.add(Pointer64DataType.dataType, "Start", null);
        row.add(Pointer64DataType.dataType, "End", null);
        row.setCategoryPath(Constants.CATEGORY_READYTORUN);

        var result = new StructureDataType("ReadyToRunHeader", 0);
        row.setCategoryPath(Constants.CATEGORY_READYTORUN);

        result.add(DWORD, "Signature", null);
        result.add(WORD, "MajorVersion", null);
        result.add(WORD, "MinorVersion", null);
        result.add(DWORD, "Flags", null);
        result.add(WORD, "NumberOfSections", null);
        result.add(BYTE, "EntrySize", null);
        result.add(BYTE, "EntryType", null);

        result.add(new ArrayDataType(row, _sections.length), "Sections", null);

        return result;
    }

}