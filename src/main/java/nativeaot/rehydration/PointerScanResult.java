package nativeaot.rehydration;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;


public class PointerScanResult {
    private final AddressRange hydratedRange;
    private final Address[] pointerLocations;

    public PointerScanResult(AddressRange hydratedRange, Address[] pointerLocations) {
        this.hydratedRange = hydratedRange;
        this.pointerLocations = pointerLocations;
    }

    public AddressRange getScanningRange() {
        return hydratedRange;
    }

    public Address[] getPointerLocations() {
        return pointerLocations;
    }    
}