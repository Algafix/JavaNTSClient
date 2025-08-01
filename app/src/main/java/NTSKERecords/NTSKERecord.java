package NTSKERecords;

public class NTSKERecord {
    public int criticalBit;
    public int recordType_raw;
    public NTSKERecordType recordType;
    public int bodyLength;
    public byte[] recordBody;

    /**
     * Constructor for NTSKERecord from arbitrary parameters.
     * @param criticalBit 0 or 1 to indicate if an error should be raised if the record is not understood.
     * @param recordType the type of the record, as defined in NTSKERecordType, encoded in 15 bits.
     * @param bodyLength the length of the record body in octets, encoded in 2 bytes.
     * @param recordBody the body of the record, which can be empty.
     */
    public NTSKERecord(int criticalBit, int recordType, int bodyLength, byte[] recordBody) {
        this.criticalBit = criticalBit;
        this.recordType_raw = recordType;
        this.recordType = NTSKERecordType.fromValue(recordType);
        this.bodyLength = bodyLength;
        this.recordBody = recordBody;
    }

    /**
     * Constructor for NTSKERecord from a raw byte array.
     * @param raw_record the raw byte array containing the record data.
     */
    public NTSKERecord(byte[] raw_record) {
        criticalBit = (raw_record[0] & 0xF0) >> 7;
        recordType_raw = ((raw_record[0] & 0x7F) << 8) | (raw_record[1] & 0xFF);
        recordType = NTSKERecordType.fromValue(recordType_raw);
        bodyLength = raw_record[2] << 8 | (raw_record[3] & 0xFF);
        if(bodyLength > 0){
            recordBody = new byte[bodyLength];
            System.arraycopy(raw_record, 4, recordBody, 0, bodyLength);
        }
    }

    /**
     * Converts the NTSKERecord to a byte array to be send over the network.
     * @return the byte array representation of the record.
     */
    public byte[] toBytes(){

        byte[] record = new byte[4 + bodyLength];
        record[0] = (byte) (criticalBit << 7 | recordType_raw >> 8);
        record[1] = (byte) (recordType_raw & 0xFF);
        record[2] = (byte) (bodyLength >> 8);
        record[3] = (byte) (bodyLength & 0xFF);

        if(bodyLength > 0) {
            System.arraycopy(recordBody, 0, record, 4, bodyLength);
        }
        return record;
    }

    /**
     * Converts the NTSKERecord to a string representation for debugging purposes.
     * @return the string representation of the record.
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("NTSKERecord { ");
        sb.append("criticalBit=").append(criticalBit).append(", ");
        sb.append("recordType=").append(recordType_raw).append(' ').append(recordType).append(", ");
        sb.append("bodyLength=").append(bodyLength).append(", ");
        sb.append("recordBody=");
        if (recordBody != null) {
            for (byte b : recordBody) {
                sb.append(String.format("%02X", b));
            }
        } else {
            sb.append("null");
        }
        sb.append(" }");
        return sb.toString();
    }

    /**
     * Converts the NTSKERecord to a byte string representation for debugging purposes.
     * @return the byte string representation of the record.
     */
    public String toByteString() {
        byte[] bytes = toBytes();
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        sb.append('\n');
        return sb.toString();
    }

}
