package nativeaot.objectmodel;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;

import ghidra.app.cmd.function.CreateFunctionCmd;
import static ghidra.app.util.bin.StructConverter.DWORD;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.Pointer64DataType;
import ghidra.program.model.data.WideChar16DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import nativeaot.Constants;
import nativeaot.rehydration.PointerScanResult;

public class MethodTableCrawler {
    private static final int RELATED_TYPE_OFFSET = 0x08; // TODO: make more generic
    private static final int MAX_PASSES = 100;

    private static final String[] OBJECT_METHOD_NAMES = {
        "ToString",
        "Equals",
        "GetHashCode"
    };

    private final MethodTableManager _manager;
    private final Program _program;
    private final PointerScanResult _pointerScan;

    public MethodTableCrawler(MethodTableManager manager, Program program, PointerScanResult pointerScan) {
        _manager = manager;
        _program = program;
        _pointerScan = pointerScan;
    }

    public void analyze( TaskMonitor monitor, MessageLog log) throws Exception {
        // Our algorithm is based on the induced inheritance graph from System.Object
        if (_manager.getObjectMT() == null) {
            var objectMT = findSystemObjectMT(monitor, log);
            if (objectMT == null) {
                return;
            }

            _manager.setObjectMT(objectMT);
        }

        log.appendMsg(Constants.TAG, String.format("Assuming %s is System.Object", _manager.getObjectMT().getAddress()));

        // Find all method tables.
        findAllMTs(monitor, log);
        log.appendMsg(Constants.TAG, String.format("Found %d method tables", _manager.getMethodTableCount()));

        // Annotate some special method tables.
        assignSystemObjectNames(_manager.getObjectMT());

        if (_manager.getStringMT() == null) {
            var stringMT = findSystemStringMT(monitor, log);
            if (stringMT != null) {
                log.appendMsg(Constants.TAG, String.format("Assuming %s is System.String", stringMT.getAddress()));
                assignSystemStringNames(stringMT);
                _manager.setStringMT(stringMT);
            }
        }

        for (var mt : _manager.getMethodTables()) {
            if (mt.isSzArray()) {
                assignSzArrayNames(mt);
            }
        }

        // Create the actual data types and assign them to the method tables stored in memory.
        createMTStructures(monitor, log);
        assignMethods(monitor, log);
    }

    private MethodTable findSystemObjectMT(TaskMonitor monitor, MessageLog log) throws Exception {
        var candidates = findCandidateSystemObjectMTs(monitor);
        if (candidates.length == 0) {
            log.appendMsg(Constants.TAG, "No System.Object candidate found.");
            return null;
        } else if (candidates.length > 1) {
            log.appendMsg(Constants.TAG, "Multiple System.Object candidates found.");
            for (var candidate : candidates) {
                log.appendMsg(Constants.TAG, " - " + candidate);
            }
            return null;
        }

        return getOrCreateMethodTable(candidates[0]);
    }

    private Address[] findCandidateSystemObjectMTs(TaskMonitor monitor) throws Exception {
        // The System.Object method table has no base type, contains exactly 3 vtable slots (ToString, Equals, GetHashCode), 
        // does not reference interfaces, and sets flags to only ElementType.Class. This is a very specific signature
        // that we can use as a heuristic.

        var memory = _program.getMemory();
        var result = new ArrayList<Address>();

        var locations = _pointerScan.getPointerLocations();
        for (int i = 0; i < locations.length - 3; i++) {
            monitor.checkCancelled();

            // We're trying to match bytes relative to the pointer to Object.ToString in the vtable.
            long offset = locations[i].getOffset();

            // Check if there are at least two subsequent pointers (Equals, GetHashCode).
            if (offset + 0x08 != locations[i + 1].getOffset()
                || offset + 0x10 != locations[i + 2].getOffset()
                || offset + 0x18 == locations[i + 3].getOffset()) {
                continue;
            }

            // TODO: The following offsets are .NET 8.0 specific which should probably be abstracted away.
            try {
                // Check 3 vtable slots.
                if (memory.getShort(locations[i].subtract(0x08)) != 3) {
                    continue;
                }

                // Check 0 interfaces.
                if (memory.getShort(locations[i].subtract(0x06)) != 0) {
                    continue;
                }

                // Check base type == 0 (no base type)
                if (memory.getLong(locations[i].subtract(0x10)) != 0) {
                    continue;
                }

                // Check flags for class bit only set.
                if (memory.getInt(locations[i].subtract(0x18)) != 0x5000_0000) {
                    continue;
                }
            } catch (MemoryAccessException ex) {
                continue;
            }

            result.add(locations[i].subtract(0x18));
        }

        return result.toArray(Address[]::new);
    }

    private MethodTable getOrCreateMethodTable(Address address) throws Exception {
        var mt = _manager.getMethodTable(address);
        if (mt == null) {
            mt = _manager.createMT(address);
            mt.initFromMemory();
            mt.setGhidraClass(_manager.getOrCreateGhidraClass(mt, null));
            _manager.registerMT(mt);
        }

        return mt;
    }

    private void findAllMTs(TaskMonitor monitor, MessageLog log) throws CancelledException {
        var scanningRange = _pointerScan.getScanningRange();

        var unmatched = new ArrayList<>(Arrays.asList(_pointerScan.getPointerLocations()));
        var agenda = new ArrayList<Address>(unmatched.size());

        for (int pass = 1; pass < MAX_PASSES; pass++) {
            monitor.checkCancelled();

            agenda.clear();
            agenda.addAll(unmatched);
            unmatched.clear();

            monitor.setMessage(String.format("%s: Analyzing %d pointers in hydrated data (pass %d)...",
                Constants.TAG,
                agenda.size(),
                pass
            ));
            monitor.setIndeterminate(false);
            monitor.setProgress(0);
            monitor.setMaximum(agenda.size());
            for (int i = 0; i < agenda.size(); i++) {
                monitor.checkCancelled();
                monitor.setProgress(i);

                var current = agenda.get(i);

                // Read the pointer at the reference.
                long dereferenced;
                try {
                    dereferenced = _program.getMemory().getLong(current);
                } catch (MemoryAccessException ex) {
                    // Broken reference, ignore.
                    continue;
                }

                // Check if it resides in the same range data.
                if (scanningRange.getMinAddress().getOffset() > dereferenced 
                    || dereferenced > scanningRange.getMaxAddress().getOffset()) {
                    // This is not a pointer that resides in the hydrated data (could be code entry point pointer of a method).
                    // This can therefore never be a method table reference.
                    continue;
                }

                // Check if this is a known method table.
                var relatedType = _manager.getMethodTable(dereferenced);
                if (relatedType == null) {
                    // Not known (yet), put it back in the potential method table refs queue.
                    unmatched.add(current);
                    continue;
                }

                MethodTable mt;
                try {
                    mt = getOrCreateMethodTable(current.subtract(RELATED_TYPE_OFFSET));
                    mt.setRelatedType(relatedType);
                } catch (Exception ex) {
                    // This is not a valid method table.
                    continue;
                }

                for (var iface: mt.getInterfaceAddresses()) {
                    if (iface == 0) {
                        continue;
                    }
                    try {
                        var x = getOrCreateMethodTable(current.getNewAddress(iface));
                        mt.getInterfaces().add(x);
                    } catch (Exception ex) {
                        // This is not a valid method table.
                        continue;
                    }
                }
            }

            if (unmatched.size() >= agenda.size()) {
                // log.appendMsg("No changes detected, breaking out of loop.");
                break;
            }
        }

        monitor.setProgress(monitor.getMaximum());
    }


    private MethodTable findSystemStringMT(TaskMonitor monitor, MessageLog log) {
        var candidates = findSystemStringCandidates(monitor);

        if (candidates.length == 0) {
            log.appendMsg(Constants.TAG, "No System.String candidate found.");
            return null;
        } else if (candidates.length > 1) {
            log.appendMsg(Constants.TAG, "Multiple System.String candidates found.");
            for (var candidate : candidates) {
                log.appendMsg(Constants.TAG, " - " + candidate.getAddress());
            }
            return null;
        }

        return candidates[0];
    }

    private MethodTable[] findSystemStringCandidates(TaskMonitor monitor) {
        var candidates = new ArrayList<MethodTable>();

        for (var mt: _manager.getMethodTables()) {
            if (mt.getRelatedType() == _manager.getObjectMT() // Directly derived from System.Object
                && mt.getElementType() == ElementType.CLASS   // class definition
                && mt.getBaseSize() == 0x16)                  // Specific (smaller!) base size.
            {
                candidates.add(mt);
            }
        }

        return candidates.toArray(MethodTable[]::new);
    }

    private void createMTStructures(TaskMonitor monitor, MessageLog log) throws Exception {
        monitor.setMessage(String.format("%s: Processing %d method table structures...",
            Constants.TAG,
            _manager.getMethodTableCount()
        ));

        monitor.setProgress(0);
        monitor.setIndeterminate(false);
        monitor.setMaximum(_manager.getMethodTableCount());

        for (var table : _manager.getMethodTables()) {
            monitor.increment();

            try {
                table.commitToDB();
            } catch (Exception ex) {
                log.appendException(ex);
            }

            // HACK: if we don't do this, Ghidra's UI hangs...
            Thread.yield();
        }
    }

    private void assignMethods(TaskMonitor monitor, MessageLog log) throws Exception {
        // Start at the object MT and crawl down the type hierarchy tree to ensure methods of base types are renamed first.
        monitor.setMessage(String.format("%s: Assigning methods...", Constants.TAG));
        monitor.setIndeterminate(true);

        var space = _manager.getObjectMT().getAddress().getAddressSpace();
        var listing = _program.getListing();

        var visited = new HashSet<MethodTable>();
        var agenda = new ArrayDeque<MethodTable>();
        agenda.add(_manager.getObjectMT());

        while (!agenda.isEmpty()) {
            var currentMT = agenda.remove();

            // Malicious type loops safeguard
            if (!visited.add(currentMT)) {
                continue;
            }

            // Schedule derived types.
            for (var derivedMT: currentMT.getDerivedTypes()) {
                agenda.add(derivedMT);
            }

            // Ensure object type is registered.
            currentMT.getOrCreateInstanceType();

            // Ensure methods are created at every executable vtable slot.
            var vtable = currentMT.getVTable();
            for (int i = 0; i < vtable.length; i++) {
                var entryPoint = space.getAddress(vtable[i]);

                // Ensure this is a label to some executable memory.
                var block = _program.getMemory().getBlock(entryPoint);
                if (block == null || !block.isExecute()) {
                    continue;
                }

                // Get the function at the entry point or create a new one.
                var function = listing.getFunctionAt(entryPoint);
                if (function == null) {
                    try {
                        var body = CreateFunctionCmd.getFunctionBody(_program, entryPoint);
                        function = listing.createFunction(null, entryPoint, body, SourceType.ANALYSIS);
                    } catch (OverlappingFunctionException | InvalidInputException ex) {
                        continue;
                    }
                }

                // If we failed to get/make a function at the entry point, skip renaming.
                if (function == null) {
                    continue;
                }

                // Only rename if it wasn't renamed before.
                if (function.getName().startsWith("FUN_")) {
                    if (i < OBJECT_METHOD_NAMES.length) {
                        function.setName(OBJECT_METHOD_NAMES[i], SourceType.ANALYSIS);
                    } else {
                        function.setName(String.format("Method_%d", i), SourceType.ANALYSIS);
                    }
                }

                if (function.getParentNamespace() == _program.getGlobalNamespace()) {
                    function.setParentNamespace(currentMT.getGhidraClass());
                }

                // Set parent class.
                function.setCallingConvention("__thiscall");
            }
        }
    }

    private void assignSystemObjectNames(MethodTable objectMT) throws Exception {
        objectMT.setName(Constants.SYSTEM_OBJECT_NAME);

        var objectVTableChunk = objectMT.getVTableChunks().iterator().next();
        objectVTableChunk.getMethod(0).setName("ToString");
        objectVTableChunk.getMethod(1).setName("Equals");
        objectVTableChunk.getMethod(2).setName("GetHashCode");
    }

    private void assignSystemStringNames(MethodTable stringMT) throws Exception {
        // https://github.com/dotnet/runtime/blob/50c020e4f0f03a801c137fca5ba7f0f052f3c7e9/src/coreclr/nativeaot/Runtime.Base/src/System/String.cs#L56

        stringMT.setName(Constants.SYSTEM_STRING_NAME);

        var instanceType = stringMT.getOrCreateInstanceType();
        instanceType.deleteAll();
        instanceType.add(new Pointer64DataType(stringMT.getOrCreateMTType()), "mt", null);
        instanceType.add(DWORD, "_length", null);
        instanceType.add(new ArrayDataType(WideChar16DataType.dataType, 0), "_firstChar", null);
    }

    private void assignSzArrayNames(MethodTable szArrayMT) throws Exception  {
        // https://github.com/dotnet/runtime/blob/50c020e4f0f03a801c137fca5ba7f0f052f3c7e9/src/coreclr/nativeaot/Runtime.Base/src/System/Array.cs#L31

        var instanceType = szArrayMT.getOrCreateInstanceType();
        instanceType.deleteAll();
        instanceType.add(new Pointer64DataType(szArrayMT.getOrCreateMTType()), "mt", null);
        instanceType.add(DWORD, "Length", null);
        instanceType.add(DWORD, "Padding", null);
        instanceType.add(new ArrayDataType(ByteDataType.dataType, 0), "Data", null);
    }
}