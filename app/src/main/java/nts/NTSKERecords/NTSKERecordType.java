package nts.NTSKERecords;

public enum NTSKERecordType {
    EndOfMessage(0),
    NTSNextProtocolNegotiation(1),
    Error(2),
    Warning(3),
    AEADAlgorithmNegotiation(4),
    NewCookieForNTPv4(5),
    NTPv4ServerNegotiation(6),
    NTPv4PortNegotiation(7);

    private final int value;

    NTSKERecordType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static NTSKERecordType fromValue(int value) {
        for (NTSKERecordType type : NTSKERecordType.values()) {
            if (type.value == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown NTSKERecordType value: " + value);
    }
}
