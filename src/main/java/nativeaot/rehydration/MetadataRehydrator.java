
package nativeaot.rehydration;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;


public abstract class MetadataRehydrator {

    private boolean _markupRehydrationCode;

    public abstract PointerScanResult rehydrate(Program program, AddressRange dehydrated, TaskMonitor monitor, MessageLog log) throws Exception;

    public void markupRehydrationCode(boolean value) {
        _markupRehydrationCode = value;
    }

    public boolean markupRehydrationCode() {
        return _markupRehydrationCode;
    }
}