package nativeaot.objectmodel;

import java.lang.Exception;

import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.Stack;

public class Method {
    private final VTableChunk _parent;
    private final int _slotIndex;

    public Method(VTableChunk parent, int slotIndex) {
        _parent = parent;
        _slotIndex = slotIndex;
    }

    public VTableChunk getParent() {
        return _parent;
    }

    public String getName() {
        var component = getDataTypeComponent();
        return component != null
            ? component.getFieldName()
            : String.format("DETACHED_Method_%d".formatted(_slotIndex));
    }

    public int getSlotIndex() {
        return _slotIndex;
    }

    public void setName(String name) throws Exception {
        getDataTypeComponent().setFieldName(name);
    }

    public DataTypeComponent getDataTypeComponent() {
        int relativeIndex = _slotIndex - _parent.getBaseIndex();
        return _parent.getDataType().getComponentAt(relativeIndex * 8);
    }

    public Iterable<Function> getImplementingFunctions(Program program) {
        var result = new ArrayList<Function>();

        var directParent = getParent().getDirectParent();

        var agenda = new Stack<MethodTable>();
        agenda.push(directParent);

        while (!agenda.isEmpty()) {
            var current = agenda.pop();

            // Find the method stored in the vtable slot.
            if (getSlotIndex() < current.getVTableSlotCount()) {
                var methodAddress = current.getVTableSlot(getSlotIndex());
                if (methodAddress != 0) {
                    var function = program.getFunctionManager().getFunctionAt(current.getAddress().getNewAddress(methodAddress));
                    if (function != null && !result.contains(function)) {
                        result.add(function);
                    }
                }
            }

            // Crawl further down the type tree.
            for (var mt : current.getDerivedTypes()) {
                agenda.push(mt);
            }
        }

        return result;
    }

    @Override
    public String toString() {
        return getName();
    }
}
