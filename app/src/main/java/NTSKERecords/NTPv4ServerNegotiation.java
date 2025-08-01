package NTSKERecords;

public class NTPv4ServerNegotiation extends NTSKERecord {

    public String NTPv4Server;

    /**
     * Constructor for NTPv4ServerNegotiation record from a raw byte array. Verifies that the values are correct.
     * @param rawRecord the raw byte array containing the record data.
     */
    public NTPv4ServerNegotiation(byte[] rawRecord) {
        super(rawRecord);

        if (recordType != NTSKERecordType.NTPv4ServerNegotiation) {
            throw new IllegalArgumentException("Record type must be NTPv4ServerNegotiation.");
        }
        if ((bodyLength == 0) || (recordBody == null)) {
            throw new IllegalArgumentException("Body length cannot be 0 for NTPv4ServerNegotiation record.");
        }

        NTPv4Server = new String(recordBody);
    }
    
}
