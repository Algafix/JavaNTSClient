package NTSKERecords;

public class Error extends NTSKERecord {

    public Constants.ErrorCodes errorCode;

    /**
     * Constructor for Error record with default values.
     */
    public Error(Constants.ErrorCodes errorCode) {
        super(1, NTSKERecordType.Error.getValue(), 2, errorCode.getBytesValue());
        this.errorCode = errorCode;
    }

    /**
     * Constructor for Error record from a raw byte array. Verifies that the values are correct.
     * @param rawRecord the raw byte array containing the record data.
     */
    public Error(byte[] rawRecord) {
        super(rawRecord);

        if (criticalBit != 1) {
            throw new IllegalArgumentException("Critical bit must be set to 1 for Error record.");
        }
        if (recordType != NTSKERecordType.Error) {
            throw new IllegalArgumentException("Record type must be Error.");
        }
        if ((bodyLength != 2) || (recordBody == null)) {
            throw new IllegalArgumentException("Body length must be 2 for Error record.");
        }

        errorCode = Constants.ErrorCodes.fromBytes(recordBody);
    }
    
}
