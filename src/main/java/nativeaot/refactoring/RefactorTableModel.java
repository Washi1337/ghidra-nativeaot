package nativeaot.refactoring;

import java.util.List;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.GDynamicColumnTableModel;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;

public class RefactorTableModel extends GDynamicColumnTableModel<Refactor, Object> {
    public static final int APPLY = 0;
    public static final int TYPE = 1;
    public static final int SYMBOL = 2;
    public static final int NEW_NAME = 3;

    private final List<Refactor> _refactors;

    public RefactorTableModel(ServiceProvider serviceProvider, List<Refactor> refactors) {
        super(serviceProvider);
        _refactors = refactors;
    }

    @Override
    public Object getDataSource() {
        return null;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == APPLY;
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex != APPLY) {
            return;
        }

        _refactors.get(rowIndex).setApply((boolean) aValue);
    }

    @Override
    protected TableColumnDescriptor<Refactor> createTableColumnDescriptor() {
        TableColumnDescriptor<Refactor> descriptor = new TableColumnDescriptor<>();

        descriptor.addVisibleColumn(new ApplyColumn());
        descriptor.addVisibleColumn(new TypeColumn());
        descriptor.addVisibleColumn(new OldNameColumn());
        descriptor.addVisibleColumn(new NewNameColumn());

        return descriptor;
    }

    @Override
    public String getName() {
        return "Refactors";
    }

    @Override
    public List<Refactor> getModelData() {
        return _refactors;
    }

    private class ApplyColumn extends AbstractDynamicTableColumn<Refactor, Boolean, Object> {
        @Override
        public String getColumnName() {
            return "Apply";
        }

        @Override
        public Boolean getValue(Refactor rwtp, Settings stngs, Object dtsrc, ServiceProvider sp) throws IllegalArgumentException {
            return rwtp.isApply();
        }
    }

    private class TypeColumn extends AbstractDynamicTableColumn<Refactor, String, Object> {
        @Override
        public String getColumnName() {
            return "Type";
        }

        @Override
        public String getValue(Refactor rwtp, Settings stngs, Object dtsrc, ServiceProvider sp) throws IllegalArgumentException {
            return rwtp.getRefactorType();
        }
    }

    private class OldNameColumn extends AbstractDynamicTableColumn<Refactor, String, Object> {
        @Override
        public String getColumnName() {
            return "Old Name";
        }

        @Override
        public String getValue(Refactor rwtp, Settings stngs, Object dtsrc, ServiceProvider sp) throws IllegalArgumentException {
            return rwtp.getObjectDisplayName();
        }
    }

    private class NewNameColumn extends AbstractDynamicTableColumn<Refactor, String, Object> {
        @Override
        public String getColumnName() {
            return "New Name";
        }

        @Override
        public String getValue(Refactor rwtp, Settings stngs, Object dtsrc, ServiceProvider sp) throws IllegalArgumentException {
            return rwtp.getSuggestedDisplayName();
        }
    }

}
