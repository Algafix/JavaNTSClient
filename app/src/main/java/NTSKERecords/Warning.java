package NTSKERecords;

public class Warning extends NTSKERecord {

    /**
     * Constructor for Warning record with default values.
     */
    public Warning(int warningCode) {
        super(1, NTSKERecordType.Warning.getValue(), 2, new byte[2]);
        byte[] warningBody = new byte[2];
        warningBody[0] = (byte) (warningCode >> 8);
        warningBody[1] = (byte) (warningCode & (byte) 0xFF);
        this.recordBody = warningBody;
    }

    /**
     * Constructor for Warning record from a raw byte array. Verifies that the values are correct.
     * @param rawRecord the raw byte array containing the record data.
     */
    public Warning(byte[] rawRecord) {
        super(rawRecord);

        if (criticalBit != 1) {
            throw new IllegalArgumentException("Critical bit must be set to 1 for Warning record.");
        }
        if (recordType != NTSKERecordType.Warning) {
            throw new IllegalArgumentException("Record type must be Warning.");
        }
        if ((bodyLength != 2) || (recordBody == null)) {
            throw new IllegalArgumentException("Body length must be 2 for Warning record.");
        }
    }
    
}
