package nativeaot.browser;

import java.awt.BorderLayout;
import java.awt.event.MouseEvent;
import java.util.ArrayList;

import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.WindowPosition;
import docking.action.builder.ActionBuilder;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeSelectionEvent;
import ghidra.app.context.ProgramActionContext;
import ghidra.program.model.listing.Program;
import nativeaot.NativeAotPlugin;
import nativeaot.objectmodel.MethodTable;
import resources.Icons;

public class MetadataBrowserProvider extends ComponentProvider {

    private JPanel _panel;
    private GTreeNode _rootNode;
    private final NativeAotPlugin _plugin;
    private GTree _tree;

    public MetadataBrowserProvider(NativeAotPlugin plugin) {
        super(plugin.getTool(), "Native AOT Metadata", plugin.getName());
        _plugin = plugin;
		setDefaultWindowPosition(WindowPosition.LEFT);

        buildPanel();
        buildActions();
    }

    private void buildPanel() {
        _panel = new JPanel(new BorderLayout());

        _rootNode = new GenericNode("Types");

        _tree = new GTree(_rootNode);
        _tree.addGTreeSelectionListener((GTreeSelectionEvent gtse) -> {
            if (gtse.getPath() == null) {
                return;
            }

            var last = gtse.getPath().getLastPathComponent();
            if (last instanceof AddressNode node) {
                if (node.getAddress().getOffset() != 0) {
                    _plugin.navigate(node.getAddress());
                }
            }
        });
        _panel.add(_tree);

        setVisible(true);
    }

    @Override
    public JComponent getComponent() {
        return _panel;
    }

    private void buildActions() {
        buildRefreshAction();
    }

    private void buildRefreshAction() {
        new ActionBuilder("Refresh", _plugin.getName())
                .toolBarIcon(Icons.REFRESH_ICON)
                .enabled(true)
                .onAction(c -> {
                    var manager = _plugin.getMainMethodTableManager();
                    if (manager == null) {
                        return;
                    }

                    manager.restoreFromDB();
                    rebuildTree();
                })
                .buildAndInstallLocal(this);
        new ActionBuilder("Rename", _plugin.getName())
                .enabled(true)
                .withContext(Context.class)
                .popupMenuPath(new String[] { "Rename" })
                .popupMenuGroup("xxx", "1")
                .enabledWhen(c -> {
                    var path = c.getTree().getSelectionPath();
                    if (path == null) {
                        return false;
                    }

                    var last = path.getLastPathComponent();
                    return last instanceof TypeNode
                        || last instanceof MethodNode;
                })
                .onAction(c -> {
                    c.getTree().startEditing(c.getTree().getSelectedNodes().getFirst());
                })
                .buildAndInstallLocal(this);
    }

    public void rebuildTree() {
        boolean expanded = _rootNode.isExpanded();
        _rootNode.removeAll();

        var manager = _plugin.getMainMethodTableManager();
        if (manager == null) {
            return;
        }

        var sorted = new ArrayList<MethodTable>();
        for (var mt : manager.getMethodTables()) {
            sorted.add(mt);
        }
        sorted.sort((a, b) -> a.getName().compareTo(b.getName()));
        
        for (var mt : sorted) {
            _rootNode.addNode(new TypeNode(mt));
        }

        if (expanded) {
            _rootNode.expand();
        }
    }

    @Override
    public ActionContext getActionContext(MouseEvent event) {
        return new Context(this, _plugin.getCurrentProgram(), _tree);
    }

    class Context extends ProgramActionContext {

        private final GTree _tree;

        public Context(ComponentProvider provider, Program program, GTree tree) {
            super(provider, program);
            _tree = tree;
        }

        public GTree getTree() {
            return _tree;
        }
    }
}
