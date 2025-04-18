package nativeaot.refactoring;

import nativeaot.objectmodel.MethodTable;

public class MethodTableRefactor extends Refactor {

    public MethodTableRefactor(MethodTable mt, String suggestedName) {
        super(mt, suggestedName);
    }

    public MethodTable getMT() {
        return (MethodTable) getObject();
    }

    @Override
    public String getObjectDisplayName() {
        return getMT().getName();
    }

    @Override
    public String getRefactorType() {
        return "Method Table";
    }

    @Override
    public void apply() throws Exception {
        getMT().setName(getSuggestedName());
    }
}
