
package nativeaot.objectmodel.net80;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import nativeaot.Constants;
import nativeaot.objectmodel.MethodTable;
import nativeaot.objectmodel.MethodTableManager;

public class MethodTableManagerNet80 extends MethodTableManager {

    public MethodTableManagerNet80(Program program) {
        super(program);
    }

    @Override
    public MethodTable createMT(Address address) {
        return new MethodTableNet80(this, address);
    }

    @Override
    public void restoreFromDB() {
        clear();

        var dataTypeManager = getProgram().getDataTypeManager();
        var space = getProgram().getAddressFactory().getDefaultAddressSpace(); // TODO: verify
        var naotCategory = dataTypeManager.getCategory(Constants.CATEGORY_NATIVEAOT);
        var mtCategory = dataTypeManager.getCategory(Constants.CATEGORY_METHOD_TABLES);

        if (naotCategory == null || mtCategory == null) {
            return;
        }

        // Restore all MT types and addresses from DT manager.
        for (var mtType: mtCategory.getDataTypes()) {
            if (!mtType.getName().endsWith("_MT")) {
                continue;
            }
            var name = mtType.getName().substring(0, mtType.getName().length() - 3);

            Address address;
            try {
                address = space.getAddress(mtType.getDescription());
            } catch (Exception ex) {
                continue;
            }

            var mt = createMT(address);
            try {
                mt.initFromMemory();
                mt.setGhidraClass(getOrCreateGhidraClass(mt, name));
            } catch (Exception ex) {
                continue;
            }

            registerMT(mt);

            switch (name) {
                case Constants.SYSTEM_OBJECT_NAME -> setObjectMT(mt);
                case Constants.SYSTEM_STRING_NAME -> setStringMT(mt);
            }
        }

        // Rebuild type inheritance graph.
        for (var mt : getMethodTables()) {
            mt.setRelatedType(getMethodTable(mt.getRelatedTypeAddress()));

            mt.getInterfaces().clear();
            for (var iface: mt.getInterfaceAddresses()) {
                if (iface == 0) {
                    continue;
                }

                var interfaceMT = getMethodTable(iface);
                if (interfaceMT == null) {
                    continue;
                }

                mt.getInterfaces().add(interfaceMT);
            }
        }

        // Link all MTs to the database.
        for (var mt : getMethodTables()) {
            try {
                mt.commitToDB();
            } catch (Exception e) {
                Msg.error(Constants.TAG, "Failed to commit %s".formatted(mt), e);
            }
        }
    }

}