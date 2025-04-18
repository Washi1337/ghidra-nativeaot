package nativeaot.refactoring;

import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class SymbolRefactor extends Refactor {
    public SymbolRefactor(Symbol symbol, String suggestedName) {
        super(symbol, suggestedName);
    }

    private Symbol getSymbol() {
        return (Symbol) getObject();
    }

    @Override
    public String getObjectDisplayName() {
        return "%s::%s".formatted(getSymbol().getParentNamespace().getName(), getSymbol().getName());
    }

    @Override
    public String getSuggestedDisplayName() {
        return "%s::%s".formatted(getSymbol().getParentNamespace().getName(), getSuggestedName());
    }

    @Override
    public String getRefactorType() {
        return "Symbol";
    }

    @Override
    public void apply() throws Exception {
        getSymbol().setName(getSuggestedName(), SourceType.USER_DEFINED);
    }
}
