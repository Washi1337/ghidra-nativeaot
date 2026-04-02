package nativeaot.browser;

import docking.widgets.tree.GTreeNode;
import ghidra.program.model.address.Address;
import nativeaot.objectmodel.ElementType;
import nativeaot.objectmodel.MethodTable;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class TypeReferenceNode extends AddressNode {

    private final MethodTable _mt;

    public TypeReferenceNode(MethodTable mt) {
        _mt = mt;
    }

    @Override
    public Address getAddress() {
        return _mt.getAddress();
    }

    @Override
    public String getName() {
        return _mt.getName();
    }

    @Override
    public boolean isLeaf() {
        return false;
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
    protected List<GTreeNode> generateChildren() {
        var result = new ArrayList<GTreeNode>();

        if (_mt.getRelatedType() != null) {
            result.add(new TypeReferenceNode(_mt.getRelatedType()));
        }

        for (var iface: _mt.getInterfaces()) {
            result.add(new TypeReferenceNode(iface));
        }

        return result;
    }
}
