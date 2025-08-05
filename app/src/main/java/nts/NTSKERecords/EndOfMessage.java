package nts.NTSKERecords;

public class EndOfMessage extends NTSKERecord {

    /**
     * Constructor for EndOfMessage record with default values.
     */
    public EndOfMessage() {
        super(1, NTSKERecordType.EndOfMessage.getValue(), 0, null);
    }

    /**
     * Constructor for EndOfMessage record from a raw byte array. Verifies that the values are correct.
     * @param rawRecord the raw byte array containing the record data.
     */
    public EndOfMessage(byte[] rawRecord) {
        super(rawRecord);

        if (criticalBit != 1) {
            throw new IllegalArgumentException("Critical bit must be set to 1 for EndOfMessage record.");
        }
        if (recordType != NTSKERecordType.EndOfMessage) {
            throw new IllegalArgumentException("Record type must be EndOfMessage.");
        }
        if ((bodyLength != 0) || (recordBody != null)) {
            throw new IllegalArgumentException("Body length must be 0 for EndOfMessage record.");
        }
    }
}
