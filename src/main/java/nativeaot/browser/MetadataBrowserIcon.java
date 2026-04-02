package nativeaot.browser;

import generic.theme.GIcon;
import resources.ResourceManager;

import javax.swing.*;

public class MetadataBrowserIcon {
    public static final Icon ROOT_TYPES_ICON = new GIcon("icon.plugin.symboltree.node.category.exports.closed");
    public static final Icon BASE_TYPES_ICON = new GIcon("icon.plugin.symboltree.node.category.imports.closed");
    public static final Icon CLASS_ICON = ResourceManager.loadImage("images/mdclass.png");
    public static final Icon INTERFACE_ICON = ResourceManager.loadImage("images/interface.png");
    public static final Icon STRUCT_ICON = ResourceManager.loadImage("images/struct.png");
    public static final Icon ENUM_ICON = ResourceManager.loadImage("images/enum.png");
    public static final Icon ARRAY_ICON = ResourceManager.loadImage("images/array.png");
}
