package nativeaot.browser;

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;

class GenericNode extends GTreeNode {
    private final String _header;
    private final Icon _icon;

    public GenericNode(String header, Icon icon) {
        _header = header;
        _icon = icon;
    }

    @Override
    public String getName() {
        return _header;
    }

    @Override
    public Icon getIcon(boolean bln) {
        return _icon;
    }

    @Override
    public String getToolTip() {
        return null;
    }

    @Override
    public boolean isLeaf() {
        return getChildCount() == 0;
    }

    @Override
    protected List<GTreeNode> generateChildren() {
        return new ArrayList<>();
    }
}
