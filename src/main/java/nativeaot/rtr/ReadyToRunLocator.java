
package nativeaot.rtr;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public interface ReadyToRunLocator {
    Address[] locateModules(Program program, TaskMonitor monitor, MessageLog log);
}