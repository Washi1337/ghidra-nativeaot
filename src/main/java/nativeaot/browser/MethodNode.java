package nativeaot.browser;

import javax.swing.Icon;

import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import nativeaot.Constants;
import nativeaot.objectmodel.Method;
import nativeaot.objectmodel.MethodTable;
import resources.ResourceManager;

public class MethodNode extends AddressNode {

    private static final Icon ICON = ResourceManager.loadImage("images/method.png");

    private final MethodTable _mt;
    private final Method _method;
    private final Address _address;

    public MethodNode(MethodTable mt, Method method, long address) {
        _mt = mt;
        _method = method;
        _address = mt.getAddress().getNewAddress(address);
    }

    @Override
    public String getName() {
        var method = getMethod();

        String suffix = getSuffix();
        return suffix != null
            ? "%s (%s)".formatted(method.getName(), suffix)
            : method.getName();
    }

    private String getSuffix() {
        // Abstract methods are methods with no entry point address assigned.
        if (_address.getOffset() == 0) {
            return "abstract";
        }

        // Check if this method was inherited from another class.
        var function = _mt.getManager()
            .getProgram()
            .getFunctionManager()
            .getFunctionAt(_address);

        if (function != null && !function.getParentNamespace().getName().equals(_mt.getGhidraClass().getName())) {
           return function.getParentNamespace().getName();
        }

        return null;
    }

    @Override
    public void valueChanged(Object newValue) {
        String name = newValue.toString();

        // Strip off suffix if present.
        String suffix = getSuffix();
        if (suffix != null) {
            String formattedSuffix = " (%s)".formatted(suffix);
            if (name.endsWith(formattedSuffix)) {
                name = name.substring(0, name.length() - formattedSuffix.length()).trim();
            }
        }

        // Did we change at all?
        if (getMethod().getName().equals(name)) {
            return;
        }

        final String finalName = name;

        try {
            var program = getMethod().getParent().getDirectParent().getManager().getProgram();
            program.withTransaction("Rename Method", () -> getMethod().setName(finalName));
        } catch (Exception e) {
            Msg.showError(Constants.TAG, null, "Rename failed", "Rename of method %s failed".formatted(getMethod().getName()), e);
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
        return ICON;
    }

    @Override
    public String getToolTip() {
        return null;
    }

    @Override
    public boolean isLeaf() {
        return true;
    }

    public Method getMethod() {
        return _method;
    }

    @Override
    public Address getAddress() {
        return _address;
    }
}