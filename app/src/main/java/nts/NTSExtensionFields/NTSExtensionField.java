package nts.NTSExtensionFields;

import java.util.Arrays;

public class NTSExtensionField {

    public FieldType fieldType;
    private int fieldLength;
    public byte[] body;

    /**
     * Constructor for NTSExtensionField from arbitrary parameters.
     */
    public NTSExtensionField(FieldType fieldType, byte[] body) {
        this.fieldType = fieldType;
        this.fieldLength = body.length + 4; // 2 bytes for field type, 2 bytes for length
        this.body = body;
    }

    public static NTSExtensionField fromBytes(byte []buf, int idx)
    {

        int num_bytes = buf.length;
        int remaining = num_bytes - idx;
        if(remaining < 4)
        {
            throw new RuntimeException();
        }
        byte []short_buf = Arrays.copyOfRange(buf, idx, idx+2);
        FieldType fieldType = FieldType.fromBytes(short_buf);
        short_buf = Arrays.copyOfRange(buf, idx+2, idx+4);
        int fieldLength = ((short_buf[0] & 0xFF) << 8) + (short_buf[1]&0xFF);

        if(remaining < fieldLength)
        {
            throw new RuntimeException();
        }
        short_buf = Arrays.copyOfRange(buf, idx+4, idx+fieldLength);

        return new NTSExtensionField(fieldType, short_buf);
    }

    /**
     * Returns the length of the extension field.
     * @return the field length.
     */
    public int getFieldLength() {
        return fieldLength;
    }

    public void replaceBody(byte[] bodySegment, int offset) {
        System.arraycopy(bodySegment, 0, body, offset, bodySegment.length);
    }

    /**
     * Converts the NTSExtensionField to a byte array to be send over the network.
     * @return the byte array representation of the record.
     */
    public byte[] toByteArray(){
        byte[] extensionField = new byte[fieldLength];
        System.arraycopy(fieldType.getBytesValue(), 0, extensionField, 0, 2);
        extensionField[2] = (byte) (fieldLength >> 8);
        extensionField[3] = (byte) (fieldLength & 0xFF);
        System.arraycopy(body, 0, extensionField, 4, body.length);

        return extensionField;
    }

    /**
     * Converts the NTSExtensionField to a string representation for debugging purposes.
     * @return the string representation of the record.
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("NTSExtensionField { ");
        sb.append("fieldType=").append(fieldType).append(", ");
        sb.append("fieldLength=").append(fieldLength).append(", ");
        sb.append("body=");
        if (body != null) {
            for (byte b : body) {
                sb.append(String.format("%02X", b));
            }
        } else {
            sb.append("null");
        }
        sb.append(" }");
        return sb.toString();
    }

    /**
     * Converts the NTSExtensionField to a byte string representation for debugging purposes.
     * @return the byte string representation of the record.
     */
    public String toByteString() {
        byte[] bytes = toByteArray();
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        sb.append('\n');
        return sb.toString();
    }
}


