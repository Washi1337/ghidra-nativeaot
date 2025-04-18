package nativeaot;

import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.bean.opteditor.OptionsVetoException;

public class NativeAotOptionsManager implements OptionsChangeListener {

    public static final String OPTIONS_NAME = "NativeAOT";

    private static final String ENABLE_REFACTORING_ENGINE_STRING = "Enable Refactoring Engine";
    private static final String ENABLE_REFACTORING_ENGINE_DESC_STRING = "Enables the automatic refactoring engine that automatically determines related symbols and suggests renames (beta).";

    private boolean _refactorEngineEnabled = false;

    public NativeAotOptionsManager(PluginTool tool) {
        var options = tool.getOptions(OPTIONS_NAME);
        options.addOptionsChangeListener(this);

        options.registerOption(ENABLE_REFACTORING_ENGINE_STRING, true, null, ENABLE_REFACTORING_ENGINE_DESC_STRING);

        readOptions(options);
    }

    @Override
    public void optionsChanged(ToolOptions toolOptions, String s, Object o, Object o1) throws OptionsVetoException {
        readOptions(toolOptions);
    }

    private void readOptions(ToolOptions options) {
        _refactorEngineEnabled = options.getBoolean(ENABLE_REFACTORING_ENGINE_STRING, true);
    }

    public boolean isRefactorEngineEnabled() {
        return _refactorEngineEnabled;
    }

    public void setRefactorEngineEnabled(boolean enableRefactoringEngine) {
        _refactorEngineEnabled = enableRefactoringEngine;
    }
}
