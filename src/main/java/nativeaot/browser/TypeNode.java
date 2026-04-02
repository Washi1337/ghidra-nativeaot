package nativeaot.browser;

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import nativeaot.Constants;
import nativeaot.objectmodel.ElementType;
import nativeaot.objectmodel.MethodTable;
import resources.ResourceManager;

public class TypeNode extends AddressNode {


    private final MethodTable _mt;

    public TypeNode(MethodTable mt) {
        _mt = mt;
    }

    @Override
    public String getName() {
        return _mt.getName();
    }

    @Override
    public void valueChanged(Object newValue) {
        try {
            var program = getMT().getManager().getProgram();
            program.withTransaction("Rename Method Table", () -> {
                getMT().setName(newValue.toString());
            });
        } catch (Exception e) {
            Msg.showError(Constants.TAG, null, "Rename failed", "Rename of method table %s failed".formatted(getMT().getName()), e);
        } finally {
            fireNodeChanged();
        }
    }

    @Override
    public boolean isEditable() {
        return true;
    }

    @Override
    public Icon getIcon(boolean bln) {
        int elementType = _mt.getElementType();
        return switch (elementType) {
            case ElementType.INTERFACE -> MetadataBrowserIcon.INTERFACE_ICON;
            case ElementType.VALUETYPE -> MetadataBrowserIcon.STRUCT_ICON;
            default -> ElementType.isPrimitive(elementType) ? MetadataBrowserIcon.ENUM_ICON
                    : ElementType.isArrayInstance(elementType) ? MetadataBrowserIcon.ARRAY_ICON
                    : MetadataBrowserIcon.CLASS_ICON;
        };
    }

    @Override
    public String getToolTip() {
        return null;
    }

    @Override
    public boolean isLeaf() {
        return false;
    }

    public MethodTable getMT() {
        return _mt;
    }

    @Override
    protected List<GTreeNode> generateChildren() {
        var result = new ArrayList<GTreeNode>();

        var baseTypes = new GenericNode("Base Types");
        if (_mt.getRelatedType() != null) {
            baseTypes.addNode(new TypeReferenceNode(_mt.getRelatedType()));
        }

        for (var iface: _mt.getInterfaces()) {
            baseTypes.addNode(new TypeReferenceNode(iface));
        }

        result.add(baseTypes);

        for (var chunk : _mt.getVTableChunks()) {
            for (var method : chunk.getMethods()) {
                var slotIndex = method.getSlotIndex();

                // Safety check.
                var address = slotIndex < _mt.getVTableSlotCount()
                    ? _mt.getVTableSlot(slotIndex)
                    : 0;

                result.add(new MethodNode(_mt, method, address));
            }
        }

        return result;
    }

    @Override
    public Address getAddress() {
        return _mt.getAddress();
    }
}