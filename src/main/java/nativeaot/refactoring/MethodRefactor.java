package nativeaot.refactoring;

import nativeaot.objectmodel.Method;

public class MethodRefactor extends Refactor {
    public MethodRefactor(Method method, String suggestedName) {
        super(method, suggestedName);
    }

    @Override
    public String getRefactorType() {
        return "VTable Member";
    }

    public Method getMethod() {
        return (Method) getObject();
    }

    @Override
    public String getObjectDisplayName() {
        return "this->mt->%s".formatted(getMethod().getDataTypeComponent().getFieldName());
    }

    @Override
    public String getSuggestedDisplayName() {
        return "this->mt->%s".formatted(getSuggestedName());
    }

    @Override
    public void apply() throws Exception {
        getMethod().setName(getSuggestedName());
    }
}

