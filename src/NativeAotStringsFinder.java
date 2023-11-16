//Annotates all System.String literals in a NativeAOT compiled .NET binary based on the provided System.String MethodTable address.
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

public class NativeAotStringsFinder extends GhidraScript {

    private static final CategoryPath CATEGORY_DOTNET   = new CategoryPath("/dotnet");
    private static final String       TYPENAME_STRING   = "System.String";
    private static final int          MAX_STRING_LENGTH = 1000;

    public void run() throws Exception {
        var listing = currentProgram.getListing();
        var stringType = getSystemStringType();

        var stringMethodTable = getSystemStringMethodTableAddress();
        if (stringMethodTable == null) {
            return;
        }

        // Iterate over all xrefs to the System.String MT.
        var it = listing
            .getCodeUnitAt(stringMethodTable)
            .getReferenceIteratorTo();

        while (it.hasNext()) {
            var reference = it.next();            
            if (reference.getReferenceType() != RefType.DATA)
                continue;

            var referrerAddress = reference.getFromAddress();

            // Is the referrer a symbol?
            var symbol = getSymbolAt(referrerAddress);
            if (symbol == null)
                continue;
            
            // Check if the length makes any sense.
            var length = getInt(referrerAddress.add(8));
            if (length <= 0 || length >= MAX_STRING_LENGTH)
                continue;

            // Verify there is a zero-terminator.
            var stringStart = referrerAddress.add(stringType.getLength());
            var stringEnd = stringStart.add(length * 2);
            if (getByte(stringEnd) != 0)
                continue;

            // Define string header and unicode data.
            clearListing​(referrerAddress, stringEnd);
            createData(referrerAddress, stringType);
            var s = createUnicodeString(stringStart);
            
            // Rename it.
            symbol = getSymbolAt(referrerAddress);
            symbol.setName("dn_" + s.getPathName(), SourceType.ANALYSIS);
        }
    }

    private Address getSystemStringMethodTableAddress() throws Exception {
        // TODO: maybe autodetect
        return askAddress("System.String Finder", "Address of System.String MethodTable:");
    }

    private DataType getSystemStringType() {
        var manager = currentProgram.getDataTypeManager();
        var result = manager.getDataType(CATEGORY_DOTNET, TYPENAME_STRING);

        if (result == null) {
            var newType = new StructureDataType​(CATEGORY_DOTNET, TYPENAME_STRING, 0);
            newType.add(Pointer64DataType.dataType, 0, "MethodTable", null);
            newType.add(IntegerDataType.dataType, 0, "Length", null);
            // we don't include the first char because it messes up the unicode view in the Listing.
            // newType.add(WideCharDataType.dataType, 0, "FirstChar", null);

            result = newType;
            manager.addDataType(result, DataTypeConflictHandler.DEFAULT_HANDLER);
        }

        return result;
    }

}
