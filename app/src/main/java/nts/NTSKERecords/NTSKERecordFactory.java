package nts.NTSKERecords;

public class NTSKERecordFactory {
    /**
     * Factory method to create an NTSKEBaseRecord from a raw byte array.
     * @param raw_record the raw byte array containing the record data.
     * @return an instance of NTSKEBaseRecord or its subclass based on the record type.
     */
    public static NTSKERecord parseRecord(byte[] raw_record) {
        int recordType = ((raw_record[0] & 0x7F) << 8) | (raw_record[1] & 0xFF);
        switch (NTSKERecordType.fromValue(recordType)) {
            case EndOfMessage:
                return new EndOfMessage(raw_record);
            case NTSNextProtocolNegotiation:
                return new NTSNextProtocolNegotiation(raw_record);
            case Error:
                return new Error(raw_record);
            case Warning:
                return new Warning(raw_record);
            case AEADAlgorithmNegotiation:
                return new AEADAlgorithmNegotiation(raw_record);
            case NewCookieForNTPv4:
                return new NewCookieForNTPv4(raw_record);
            case NTPv4ServerNegotiation:
                return new NTPv4ServerNegotiation(raw_record);
            case NTPv4PortNegotiation:
                return new NTPv4PortNegotiation(raw_record);
            default:
                throw new IllegalArgumentException("Unknown record type: " + recordType);
        }
    }

    public static NTSKERecord getEndOfMessageRecord() {
        return new EndOfMessage();
    }
    
    public static NTSKERecord getNTSNextProtocolNegotiationRecord(Constants.NTSNextProtocols protocol) {
        return new NTSNextProtocolNegotiation(protocol);
    }  

    public static NTSKERecord getErrorRecord(Constants.ErrorCodes errorCode) {
        return new Error(errorCode);
    }

    public static NTSKERecord getWarningRecord(int warningCode) {
        return new Warning(warningCode);
    }

    public static NTSKERecord getAEADAlgorithmNegotiationRecord(Constants.AEADAlgorithms algorithm) {
        return new AEADAlgorithmNegotiation(new Constants.AEADAlgorithms[] {algorithm});
    }

}
