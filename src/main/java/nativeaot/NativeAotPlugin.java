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
import nativeaot.browser.MetadataBrowserProvider;
import nativeaot.objectmodel.MethodTableManager;
import nativeaot.objectmodel.net80.MethodTableManagerNet80;
import nativeaot.refactoring.*;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class NativeAotPlugin extends ProgramPlugin {

	private final MetadataBrowserProvider _provider;
	private final RefactorEngine _refactorEngine;
	private final NativeAotOptionsManager _options;

	private MethodTableManager _manager;
    private GoToService _goToService;

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
		_refactorEngine.suspend();

		_manager = new MethodTableManagerNet80(program);
		_refactorEngine.setManager(_manager);

		_manager.restoreFromDB();
		_provider.rebuildTree();

		_refactorEngine.resume();
	}

	@Override
	protected void programDeactivated(Program program) {
		_refactorEngine.setManager(null);
		_manager = null;
		_provider.rebuildTree();
	}

	public MethodTableManager getMainMethodTableManager() {
		return _manager;
	}
}
