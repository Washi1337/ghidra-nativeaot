/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nativeaot;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import nativeaot.browser.MetadataBrowserProvider;
import nativeaot.objectmodel.MethodTableManager;
import nativeaot.objectmodel.net80.MethodTableManagerNet80;
import nativeaot.refactoring.*;
import nativeaot.rtr.ReadyToRunDirectory;
import nativeaot.rtr.SymbolReadyToRunLocator;

//@formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = ExamplesPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Metadata Browser and Refactoring Engine for Native AOT Binaries",
    description = "Metadata Browser and Refactoring Engine for Native AOT Binaries"
)
//@formatter:on
public class NativeAotPlugin extends ProgramPlugin {

    private final MetadataBrowserProvider _provider;
    private final RefactorEngine _refactorEngine;
    private final NativeAotOptionsManager _options;

    private MethodTableManager _manager;
    private GoToService _goToService;
    private Program _program;

    public NativeAotPlugin(PluginTool tool) {
        super(tool);

        _provider = new MetadataBrowserProvider(this);
        _options = new NativeAotOptionsManager(tool);
        _refactorEngine = new RefactorEngine(tool, _options);
    }

    @Override
    public void init() {
        super.init();

        _goToService = tool.getService(GoToService.class);
    }

    public void navigate(Address address) {
        _goToService.goTo(address);
    }

    @Override
    protected void programActivated(Program program) {
        _program = program;
        tryInitMethodTableManager();
    }

    @Override
    protected void programDeactivated(Program program) {
        _refactorEngine.setManager(null);
        _manager = null;
        _program = null;
        _provider.rebuildTree();
    }

    public MethodTableManager getMainMethodTableManager() {
        return _manager;
    }

    public MethodTableManager getOrCreateMainMethodTableManager() {
        if (_manager == null && _program != null) {
            tryInitMethodTableManager();
        }

        return _manager;
    }

    private void tryInitMethodTableManager() {
        // Try locate RTR header.
        Address[] candidates;
        try {
            candidates = SymbolReadyToRunLocator.instance.locateModules(_program, null, null);
        } catch (CancelledException e) {
            return;
        }

        if (candidates.length == 0) {
            return;
        }

        // Try read RTR header.
        ReadyToRunDirectory directory;
        try {
            directory = ReadyToRunDirectory.readAtAddress(_program, candidates[0]);
        } catch (Exception ex) {
            return;
        }

        // Update global manager and refactoring engine.
        _refactorEngine.suspend();

        _manager = MethodTableManager.createForDirectory(_program, directory);
        _refactorEngine.setManager(_manager);

        _manager.restoreFromDB();
        _provider.rebuildTree();

        _refactorEngine.resume();
    }
}
