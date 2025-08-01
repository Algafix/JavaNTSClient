package NTSKERecords;

public class NTPv4PortNegotiation extends NTSKERecord {

    public int NTPv4Port;

    /**
     * Constructor for NTPv4PortNegotiation record from a raw byte array. Verifies that the values are correct.
     * @param rawRecord the raw byte array containing the record data.
     */
    public NTPv4PortNegotiation(byte[] rawRecord) {
        super(rawRecord);

        if (recordType != NTSKERecordType.NTPv4PortNegotiation) {
            throw new IllegalArgumentException("Record type must be NTPv4PortNegotiation.");
        }
        if ((bodyLength != 2) || (recordBody == null)) {
            throw new IllegalArgumentException("Body length has to be 2 for NTPv4PortNegotiation record.");
        }

        // The port is stored as a 2-byte integer in the record body
        NTPv4Port = ((recordBody[0] & 0xFF) << 8) | (recordBody[1] & 0xFF);
    }
    
}
