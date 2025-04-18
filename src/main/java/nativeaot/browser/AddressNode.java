package nativeaot.browser;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import ghidra.program.model.address.Address;

public abstract class AddressNode extends GTreeNode {

    @Override
    public Icon getIcon(boolean bln) {
        return null;
    }

    @Override
    public String getToolTip() {
        return null;
    }

    public abstract Address getAddress();
}
