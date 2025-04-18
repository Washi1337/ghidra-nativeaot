package nativeaot.refactoring;

public abstract class Refactor {
    private boolean _apply;
    private Object _object;
    private String _suggestedName;

    protected Refactor(Object object, String suggestedName) {
        _apply = true;
        _object = object;
        _suggestedName = suggestedName;
    }

    public boolean isApply() {
        return _apply;
    }

    public void setApply(boolean apply) {
        _apply = apply;
    }

    public abstract String getRefactorType();

    public Object getObject() {
        return _object;
    }

    public void setObject(Object object) {
        _object = object;
    }

    public String getObjectDisplayName() {
        return getObject().toString();
    }

    public String getSuggestedName() {
        return _suggestedName;
    }

    public String getSuggestedDisplayName() {
        return getSuggestedName();
    };

    public void setSuggestedName(String suggestedName) {
        _suggestedName = suggestedName;
    }

    public abstract void apply() throws Exception;

    @Override
    public String toString() {
        return String.format("%s -> %s", _object, _suggestedName);
    }
}
