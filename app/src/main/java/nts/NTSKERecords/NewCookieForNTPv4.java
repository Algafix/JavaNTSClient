package nts.NTSKERecords;

public class NewCookieForNTPv4 extends NTSKERecord {

    /**
     * Constructor for NewCookie record from a raw byte array. Verifies that the values are correct.
     * @param rawRecord the raw byte array containing the record data.
     */
    public NewCookieForNTPv4(byte[] rawRecord) {
        super(rawRecord);

        if (criticalBit != 0) {
            throw new IllegalArgumentException("Critical bit must be set to 0 for NewCookieForNTPv4 record.");
        }
        if (recordType != NTSKERecordType.NewCookieForNTPv4) {
            throw new IllegalArgumentException("Record type must be NewCookieForNTPv4.");
        }
        if ((bodyLength == 0) || (recordBody == null)) {
            throw new IllegalArgumentException("Body length cannot be 0 for NewCookieForNTPv4 record.");
        }



    }
    
}
