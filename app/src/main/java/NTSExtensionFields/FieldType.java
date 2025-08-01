package NTSExtensionFields;

public enum FieldType {
    UNIQUE_IDENTIFIER(0x0104),
    NTS_COOKIE(0x0204),
    NTS_COOKIE_PLACEHOLDER(0x0304),
    NTS_AUTH_AND_ENC(0x0404);

    private final int value;

    FieldType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    /**
     * Returns the byte representation of the NTSNextProtocols value in 2 bytes.
     * @return a byte array containing the two-byte representation of the value.
     */
    public byte[] getBytesValue() {
        return new byte[] {
            (byte) (value >> 8),
            (byte) (value & 0xFF)
        };
    }

    public static FieldType fromValue(int value) {
        for (FieldType protocol : FieldType.values()) {
            if (protocol.value == value) {
                return protocol;
            }
        }
        throw new IllegalArgumentException("Unknown NTSNextProtocol value: " + value);
    }

    public static FieldType fromBytes(byte[] bytes) {
        if (bytes.length != 2) {
            throw new IllegalArgumentException("ErrorCode must be represented by 2 bytes.");
        }
        int value = ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);
        return fromValue(value);
    }

}

