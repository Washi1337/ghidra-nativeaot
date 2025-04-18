package nativeaot.refactoring;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.model.DomainObjectListenerBuilder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramEvent;
import ghidra.util.Msg;
import nativeaot.Constants;
import nativeaot.NativeAotOptionsManager;
import nativeaot.objectmodel.MethodTableManager;

import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;

import nativeaot.objectmodel.MethodTable;
import nativeaot.objectmodel.VTableChunk;

public class RefactorEngine
    implements DataTypeManagerChangeListener {

    private final PluginTool _tool;
    private final NativeAotOptionsManager _options;
    private final DomainObjectListener _domainObjectListener;

    private MethodTableManager _manager;
    private AutoAnalysisManager _analysisManager;
    private boolean _suspended;

    private int _symbolsRenamed = 0;

    public RefactorEngine(PluginTool tool, NativeAotOptionsManager options) {
        _tool = tool;
        _options = options;

        _domainObjectListener = new DomainObjectListenerBuilder(this)
                .ignoreWhen(this::ignoreEvents)
                .with(ProgramChangeRecord.class)
                .each(ProgramEvent.SYMBOL_RENAMED).call(this::processSymbolRenamed)
                .build();
    }

    private boolean ignoreEvents() {
        return !(_options.isRefactorEngineEnabled() && !_suspended && !_analysisManager.isAnalyzing());
    }

    public void suspend() {
        _suspended = true;
    }

    public void resume() {
        _suspended = false;
    }

    public void setManager(MethodTableManager manager) {
        if (_manager != null) {
            _analysisManager = null;
            var program = _manager.getProgram();
            program.getDataTypeManager().removeDataTypeManagerListener(this);
            program.removeListener(_domainObjectListener);
        }

        _manager = manager;

        if (_manager != null) {
            var program = _manager.getProgram();
            _analysisManager = AutoAnalysisManager.getAnalysisManager(program);
            program.getDataTypeManager().addDataTypeManagerListener(this);
            program.addListener(_domainObjectListener);
        }
    }

    private void doRefactors(String description, List<Refactor> refactors) {
        if (refactors == null || refactors.isEmpty()) {
            return;
        }

        var dialog = new RefactorDialog(_tool, description, refactors);
        _tool.showDialog(dialog);
        if (!dialog.applyRelatedSymbols()) {
            return;
        }

        final var finalRefactors = new ArrayList<Refactor>();
        for (var refactor : refactors) {
            if (refactor.isApply()) {
                finalRefactors.add(refactor);
            }
        }

        if (finalRefactors.isEmpty()) {
            return;
        }

        try {
            _manager.getProgram().withTransaction("Refactor", () -> {
                for (var refactor : finalRefactors) {
                    // HACK: prevent recursion.
                    if (refactor instanceof SymbolRefactor) {
                        _symbolsRenamed++;
                    }

                    refactor.apply();
                }
            });
        } catch (Exception e) {
            Msg.showError(Constants.TAG, null, "Refactoring failed", "Refactoring failed", e);
        } finally {
            Msg.debug(Constants.TAG, "Applied %d refactorings".formatted(_symbolsRenamed));
        }
    }

    private void processSymbolRenamed(ProgramChangeRecord record) {
        var symbol = (Symbol) record.getObject();
        var oldName = (String) record.getOldValue();

        if (_symbolsRenamed > 0) {
            _symbolsRenamed--;
            return;
        }

        var refactors = getRefactorSuggestions(symbol, oldName);
        doRefactors("%s has related symbols".formatted(oldName), refactors);
    }

    private List<Refactor> getRefactorSuggestions(Symbol symbol, String oldName) {
        var symbolType = symbol.getSymbolType();

        if (symbolType == SymbolType.CLASS) {
            return getRefactorSuggestions((GhidraClass) symbol.getObject(), oldName);
        } else if (symbolType == SymbolType.FUNCTION) {
            return getRefactorSuggestions((Function) symbol.getObject());
        }

        return null;
    }

    private List<Refactor> getRefactorSuggestions(GhidraClass clazz, String oldName) {
        var result = new ArrayList<Refactor>();

        // Check if the class is part of a MT.
        var mt = _manager.getMethodTable(clazz);
        if (mt == null) {
            return result;
        }

        var manager = _manager.getProgram().getDataTypeManager();

        // Check if MT type should be changed.
        try {
            var mtType = mt.getMTType();
            if (mtType == null) {
                String original = MethodTable.getMTName(oldName);
                mtType = manager.getDataType(Constants.CATEGORY_METHOD_TABLES, original);
                if (mtType != null) {
                    result.add(new DataTypeRefactor(mtType, MethodTable.getMTName(mt.getName())));
                }
            }
        } catch (Exception ex) {
        }

        // Check if instance type should be changed.
        try {
            var instanceType = mt.getInstanceType();
            if (instanceType == null) {
                instanceType = (Structure) manager.getDataType(Constants.CATEGORY_NATIVEAOT, oldName);
                if (instanceType != null) {
                    result.add(new DataTypeRefactor(instanceType, mt.getName()));
                }
            }
        } catch (Exception ex) {
        }

        // Check if vtable chunk type should be changed.
        try {
            var vtableType = mt.getOwnVTableChunk().getDataType();
            if (vtableType == null) {
                String original = VTableChunk.getDataTypeName(oldName);
                vtableType = (Structure) manager.getDataType(Constants.CATEGORY_METHOD_TABLES, original);
                if (vtableType != null) {
                    result.add(new DataTypeRefactor(vtableType, VTableChunk.getDataTypeName(mt.getName())));
                }
            }
        } catch (Exception ex) {
        }

        return result;
    }

    private List<Refactor> getRefactorSuggestions(Function function) {
        var result = new ArrayList<Refactor>();

        // Check if the function is part of a MT.
        if (!(function.getSymbol().getParentNamespace() instanceof GhidraClass clazz)) {
            return result;
        }

        var mt = _manager.getMethodTable(clazz);
        if (mt == null) {
            return result;
        }

        // Check if this function is related to a virtual method.
        long[] vTable = mt.getVTable();
        for (int i = 0; i < vTable.length; i++) {
            if (vTable[i] == function.getEntryPoint().getOffset()) {
                var method = mt.getMethod(i);
                if (method == null) {
                    continue;
                }

                // Found method, suggest the rename in the vtable.
                result.add(new MethodRefactor(method, function.getName()));

                // Check if there are any other functions that are the implementation of this method.
                for (var impl : method.getImplementingFunctions(function.getProgram())) {
                    if (impl != function) {
                        result.add(new SymbolRefactor(impl.getSymbol(), function.getName()));
                    }
                }
            }
        }

        return result;
    }

    @Override
    public void categoryAdded(DataTypeManager dtm, CategoryPath cp) {
    }

    @Override
    public void categoryRemoved(DataTypeManager dtm, CategoryPath cp) {
    }

    @Override
    public void categoryRenamed(DataTypeManager dtm, CategoryPath cp, CategoryPath cp1) {
    }

    @Override
    public void categoryMoved(DataTypeManager dtm, CategoryPath cp, CategoryPath cp1) {
    }

    @Override
    public void dataTypeAdded(DataTypeManager dtm, DataTypePath dtp) {
    }

    @Override
    public void dataTypeRemoved(DataTypeManager dtm, DataTypePath dtp) {
    }

    @Override
    public void dataTypeRenamed(DataTypeManager dtm, DataTypePath dtp, DataTypePath dtp1) {
    }

    @Override
    public void dataTypeMoved(DataTypeManager dtm, DataTypePath dtp, DataTypePath dtp1) {
    }

    @Override
    public void dataTypeChanged(DataTypeManager dtm, DataTypePath dtp) {
        if (ignoreEvents()) {
            return;
        }

        if (!dtp.getCategoryPath().equals(Constants.CATEGORY_METHOD_TABLES)) {
            return;
        }

        if (!(dtm.getDataType(dtp) instanceof Structure structure)) {
            return;
        }

        var program = _manager.getProgram();

        // Extract address from vtable chunk data type.
        Address address;
        try {
            address = program
                    .getAddressFactory()
                    .getDefaultAddressSpace()
                    .getAddress(structure.getDescription());
        } catch (Exception ex) {
            return;
        }

        // Resolve to MT.
        var mt = _manager.getMethodTable(address);
        if (mt == null) {
            return;
        }

        var refactors = new ArrayList<Refactor>();

        // Collect refactors that ensure all methods are synchronized with the vtable chunk data types.
        for (var chunk : mt.getVTableChunks()) {
            for (var method : chunk.getMethods()) {
                String methodName = method.getName();
                for (var function : method.getImplementingFunctions(program)) {
                    if (!function.getName().equals(methodName)) {
                        refactors.add(new SymbolRefactor(function.getSymbol(), methodName));
                    }
                }
            }
        }

        doRefactors("Methods defined in %s are related with other symbols.".formatted(mt.getName()), refactors);
    }

    @Override
    public void dataTypeReplaced(DataTypeManager dtm, DataTypePath dtp, DataTypePath dtp1, DataType dt) {
    }

    @Override
    public void favoritesChanged(DataTypeManager dtm, DataTypePath dtp, boolean bln) {
    }

    @Override
    public void sourceArchiveChanged(DataTypeManager dtm, SourceArchive sa) {
    }

    @Override
    public void sourceArchiveAdded(DataTypeManager dtm, SourceArchive sa) {
    }

    @Override
    public void programArchitectureChanged(DataTypeManager dtm) {
    }

    @Override
    public void restored(DataTypeManager dtm) {
    }
}
