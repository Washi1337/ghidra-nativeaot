package nativeaot.objectmodel;

public class ElementType {
    public static final int UNKNOWN = 0x00;
    public static final int VOID = 0x01;
    public static final int BOOLEAN = 0x02;
    public static final int CHAR = 0x03;
    public static final int SBYTE = 0x04;
    public static final int BYTE = 0x05;
    public static final int INT16 = 0x06;
    public static final int UINT16 = 0x07;
    public static final int INT32 = 0x08;
    public static final int UINT32 = 0x09;
    public static final int INT64 = 0x0A;
    public static final int UINT64 = 0x0B;
    public static final int INTPTR = 0x0C;
    public static final int UINTPTR = 0x0D;
    public static final int SINGLE = 0x0E;
    public static final int DOUBLE = 0x0F;

    public static final int VALUETYPE = 0x10;
    // Enum = 0x11; // EETypes store enums as their underlying type
    public static final int NULLABLE = 0x12;
    // Unused 0x13;

    public static final int CLASS = 0x14;
    public static final int INTERFACE = 0x15;

    public static final int SYSTEM_ARRAY = 0x16; // System.Array type

    public static final int ARRAY = 0x17;
    public static final int SZARRAY = 0x18;
    public static final int BYREF = 0x19;
    public static final int POINTER = 0x1A;
    public static final int FUNCTION_POINTER = 0x1B;

    public static boolean isValueType(int elementType) {
        return elementType >= VOID && elementType <= VALUETYPE;
    }

    public static boolean isPrimitive(int elementType) {
        return elementType >= VOID && elementType <= DOUBLE;
    }
}