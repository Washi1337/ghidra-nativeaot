package nativeaot.objectmodel;

import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Pointer64DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import nativeaot.Constants;

import java.util.ArrayList;

public class VTableChunk {
    private final MethodTable _directParent;
    private final int _baseIndex;
    private final ArrayList<Method> _methods = new ArrayList<>();
    
    public VTableChunk(MethodTable directParent, int baseIndex, int count) {
        _directParent = directParent;
        _baseIndex = baseIndex;
        
        for (int i = 0; i < count; i++) {
            _methods.add(new Method(this, _baseIndex + i));
        }
    }

    public MethodTable getDirectParent() {
        return _directParent;
    }

    public int getBaseIndex() {
        return _baseIndex;
    }

    public int size() {
        return _methods.size();
    }

    public Method getMethod(int index) {
        return _methods.get(index);
    }

    public Iterable<Method> getMethods() {
        return _methods;
    }

    public void propagateNameChange(String s) throws Exception {
        getDataType().setName(getDataTypeName(s));
    }

    private String getDataTypeName() {
        return getDataTypeName(getDirectParent().getName());
    }

    public static String getDataTypeName(String name) {
        return String.format(MethodTable.VTABLE_TABLE_FORMAT, name);
    }

    private StructureDataType constructDataType() {
        var structure = new StructureDataType(getDataTypeName(), 0);
        structure.setDescription(getDirectParent().getAddress().toString());
        structure.setCategoryPath(Constants.CATEGORY_METHOD_TABLES);

        for (var method : _methods) {
            structure.add(
                Pointer64DataType.dataType,
                "Method_%d".formatted(method.getSlotIndex()),
                null
            );
        }

        return structure;
    }

    public Structure getDataType() {
        var program = getDirectParent().getManager().getProgram();
        var dtManager = program.getDataTypeManager();
        return (Structure) dtManager.getDataType(Constants.CATEGORY_METHOD_TABLES, getDataTypeName());
    }

    public Structure getOrCreateDataType() {
        var chunkType = getDataType();

        if(!(chunkType instanceof Structure)) {
            var program = getDirectParent().getManager().getProgram();
            var dtManager = program.getDataTypeManager();

            chunkType = program.withTransaction("Create VTable Chunk %s".formatted(getDirectParent().getAddress()), () -> {
                return (Structure) dtManager.addDataType(
                    constructDataType(),
                    DataTypeConflictHandler.KEEP_HANDLER
                );
            });
        }

        return chunkType;
    }
}
