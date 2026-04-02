package nativeaot.objectmodel.net70;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;
import nativeaot.objectmodel.MethodTable;
import nativeaot.objectmodel.MethodTableManager;
import nativeaot.rehydration.PointerScanResult;

import java.util.ArrayList;

public class MethodTableManagerNet70 extends MethodTableManager {
    public MethodTableManagerNet70(Program program) {
        super(program);
    }

    @Override
    public MethodTable createMT(Address address) {
        return new MethodTableNet70(this, address);
    }

    @Override
    protected Address[] findCandidateSystemObjectMTs(PointerScanResult pointerScan, TaskMonitor monitor) throws Exception {
        // The System.Object method table has no base type, contains exactly 3 vtable slots (ToString, Equals, GetHashCode),
        // does not reference interfaces, and sets flags to only ElementType.Class. This is a very specific signature
        // that we can use as a heuristic.

        var memory = getProgram().getMemory();
        long[] candidateVTable = new long[4];

        var result = new ArrayList<Address>();

        var locations = pointerScan.getPointerLocations();
        for (int i = 0; i < locations.length - 3; i++) {
            monitor.checkCancelled();

            // We're trying to match bytes relative to the pointer to Object.ToString in the vtable, as the
            // Object.ToString pointer is very likely to be present in all binaries:
            //  dOff    Type      Expected value                Descr
            //  -0x18   dw        0000h                         usComponentSize
            //  -0x16   dw        A100                          usFlags (== CLASS)
            //  -0x14   ddw       18h                           uBaseSize
            //  -0x10   addr      00000000                      relatedType
            //  -0x08   dw        3h                            usNumVtableSlots
            //  -0x06   dw        0h                            usNumInterfaces
            //  -0x04   ddw       ????????h                     uHashCode
            //  +0x00   addr      &System_Object::ToString      VTable[0]
            //  +0x04   addr      &System_Object::Equals        VTable[1]
            //  +0x08   addr      &System_Object::GetHashCode   VTable[2]
            //  +0x10   ??        <not a pointer>               ??
            try {
                // Check if there are at least two subsequent pointers (Equals, GetHashCode) followed by a non-pointer.
                // Note that we cannot use locations[i+1] etc. here because some vtable entries may be 0 if the method
                // was trimmed away (e.g., this happens  with smaller binaries that do not use Object.Equals)
                memory.getLongs(locations[i], candidateVTable);
                if (!(isLikelyCodePointer(pointerScan, candidateVTable[0])
                        && isLikelyCodePointer(pointerScan, candidateVTable[1])
                        && isLikelyCodePointer(pointerScan, candidateVTable[2])
                        && !isLikelyCodePointer(pointerScan, candidateVTable[3]))) {
                    continue;
                }

                // Check vtable slot count == 3.
                if (memory.getShort(locations[i].subtract(0x08)) != 3) {
                    continue;
                }

                // Check interface count == 3.
                if (memory.getShort(locations[i].subtract(0x06)) != 0) {
                    continue;
                }

                // Check base type == 0 (no base type)
                if (memory.getLong(locations[i].subtract(0x10)) != 0) {
                    continue;
                }

                // Check base size == 0x18
                if (memory.getInt(locations[i].subtract(0x14)) != 0x18) {
                    continue;
                }

                // Check flags and component size for class bit only set.
                if (memory.getInt(locations[i].subtract(0x18)) != 0xA100_0000) {
                    continue;
                }
            } catch (MemoryAccessException ex) {
                continue;
            }

            result.add(locations[i].subtract(0x18));
        }

        return result.toArray(Address[]::new);
    }
}
