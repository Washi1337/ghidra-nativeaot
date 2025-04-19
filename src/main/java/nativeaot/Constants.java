package nativeaot;

import ghidra.program.model.data.CategoryPath;

public class Constants {
    public static final String NAME = "Native AOT Analyzer";
    public static final String TAG = "NativeAOT";

    public static final CategoryPath CATEGORY_READYTORUN = new CategoryPath("/rtr");
    public static final CategoryPath CATEGORY_NATIVEAOT = new CategoryPath("/NativeAOT");
    public static final CategoryPath CATEGORY_METHOD_TABLES = new CategoryPath("/NativeAOT/MethodTables");

    public static final String READY_TO_RUN_MODULES_START_SYMBOL_NAME = "__modules_a";
    public static final String READY_TO_RUN_MODULES_END_SYMBOL_NAME = "__modules_z";
    public static final String READY_TO_RUN_HEADER_SYMBOL_NAME = "__ReadyToRunHeader";
    public static final String DEHYDRATED_DATA_SYMBOL_NAME = "__dehydrated_data";
    public static final String HYDRATED_DATA_SYMBOL_NAME = "__hydrated_data";
    public static final String FROZEN_SEGMENT_START_SYMBOL_NAME = "__FrozenSegmentStart";

    public static final int READY_TO_RUN_SIGNATURE = 0x00525452;

    public static final String SYSTEM_OBJECT_NAME = "System_Object";
    public static final String SYSTEM_STRING_NAME = "System_String";
}