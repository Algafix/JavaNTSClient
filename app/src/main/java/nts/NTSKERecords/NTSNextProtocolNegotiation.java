package nts.NTSKERecords;

public class NTSNextProtocolNegotiation extends NTSKERecord {

    public Constants.NTSNextProtocols NTSProtocol;

    /**
     * Constructor for NTSNextProtocolNegotiation record with default values.
     */
    public NTSNextProtocolNegotiation(Constants.NTSNextProtocols protocol) {
        super(1, NTSKERecordType.NTSNextProtocolNegotiation.getValue(), 2, protocol.getBytesValue());
        this.NTSProtocol = protocol;
    }

    /**
     * Constructor for NTSNextProtocolNegotiation record from a raw byte array. Verifies that the values are correct.
     * @param rawRecord the raw byte array containing the record data.
     */
    public NTSNextProtocolNegotiation(byte[] rawRecord) {
        super(rawRecord);

        if (criticalBit != 1) {
            throw new IllegalArgumentException("Critical bit must be set to 1 for NTSNextProtocolNegotiation record.");
        }
        if (recordType != NTSKERecordType.NTSNextProtocolNegotiation) {
            throw new IllegalArgumentException("Record type must be NTSNextProtocolNegotiation.");
        }
        if ((bodyLength != 2) || (recordBody == null)) {
            throw new IllegalArgumentException("Body record is 0. Unsuported NTS Protocol by the server.");
        }

        NTSProtocol = Constants.NTSNextProtocols.fromBytes(recordBody);
    }
    
}
