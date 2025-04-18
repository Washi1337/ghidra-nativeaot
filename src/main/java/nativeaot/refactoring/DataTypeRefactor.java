package nativeaot.refactoring;

import ghidra.program.model.data.DataType;

public class DataTypeRefactor extends Refactor {

    public DataTypeRefactor(DataType dt, String newName) {
        super(dt, newName);
    }

    private DataType getSymbol() {
        return (DataType) getObject();
    }

    @Override
    public String getRefactorType() {
        return "Data Type";
    }

    @Override
    public void apply() throws Exception {
        getSymbol().setName(getSuggestedName());
    }
    
}
