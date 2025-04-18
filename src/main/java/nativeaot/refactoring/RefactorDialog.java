package nativeaot.refactoring;

import java.awt.BorderLayout;
import java.awt.event.KeyEvent;
import java.util.List;

import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.border.EmptyBorder;

import docking.DialogComponentProvider;
import docking.widgets.table.GTable;
import docking.widgets.table.TableSortState;
import ghidra.framework.plugintool.PluginTool;

public class RefactorDialog extends DialogComponentProvider {

    private boolean _applyPressed;
    private JCheckBox _checkBox;
    private GTable _table;

    public RefactorDialog(PluginTool tool, String header, List<Refactor> suggested) {
        super("Refactor related symbols", true);

        addWorkPanel(buildMainPanel(tool, header, suggested));
        addApplyButton();
        addCancelButton();
    }

    @Override
    protected void applyCallback() {
        _applyPressed = true;
        closeDialog();
    }

    public boolean applyRelatedSymbols() {
        return _applyPressed && _checkBox.isSelected();
    }

    private JComponent buildMainPanel(PluginTool tool, String header, List<Refactor> suggested) {
        var mainPanel = new JPanel(new BorderLayout());

        // Table.
        var model = new RefactorTableModel(tool, suggested);
        model.setTableSortState(TableSortState.createDefaultSortState(RefactorTableModel.TYPE));
        _table = new GTable(model);

        var scrollPane = new JScrollPane(_table);
        mainPanel.add(scrollPane, BorderLayout.CENTER);

        // Top bar
        var topPanel = new JPanel(new BorderLayout());
        topPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        var label = new JLabel(header);
        label.setBorder(new EmptyBorder(5, 0, 5, 0));
        topPanel.add(label, BorderLayout.NORTH);

        _checkBox = new JCheckBox("Rename related symbols.");
        _checkBox.setBorder(new EmptyBorder(5, 0, 5, 0));
        _checkBox.setMnemonic(KeyEvent.VK_R);
        _checkBox.setDisplayedMnemonicIndex(0);
        _checkBox.setSelected(true);
        _checkBox.addChangeListener(e -> _table.setEnabled(_checkBox.isSelected()));
        topPanel.add(_checkBox, BorderLayout.SOUTH);

        mainPanel.add(topPanel, BorderLayout.NORTH);

        return mainPanel;
    }
}