package nts;

import nts.NTSExtensionFields.NTSExtensionField;
import java.util.ArrayList;
import java.util.List;

/**
 * Implements {@link NtpV3Packet} to convert Java objects to and from the Network Time Protocol (NTP) data message header format described in RFC-1305.
 */
public class NtpV4Impl extends NtpV3Impl implements NtpV4Packet {
    private static final int EF_INDEX = 48;

    public List<NTSExtensionField> extensionFields = new ArrayList<>();

    /** Creates a new instance of NtpV4Impl */
    public NtpV4Impl() {
        setVersion(4); // NtpV4
    }

    public void addExtensionField(NTSExtensionField field)
    {
        int idx = buf.length;
        int len = field.getFieldLength();

        byte []new_buf = new byte[idx+len];
        extensionFields.add(field);

        byte []bb = field.toByteArray();
        System.arraycopy(buf, 0, new_buf, 0, idx);
        System.arraycopy(bb, 0, new_buf, idx, field.getFieldLength());

        buf = new_buf;
    }

    public void addExtensionFields(List<NTSExtensionField> fields)
    {
        int extLen = 0;
        for (NTSExtensionField ef : extensionFields) {
            extLen += ef.getFieldLength();
        }
        if(extLen == 0)
        {
            return;
        }

        byte[] new_buf = new byte[buf.length + extLen];
        System.arraycopy(buf, 0, new_buf, 0, buf.length);
        int offset = buf.length;
        for (NTSExtensionField ef : extensionFields) {
            byte[] fieldBytes = ef.toByteArray();
            System.arraycopy(fieldBytes, 0, new_buf, offset, fieldBytes.length);
            offset += fieldBytes.length;
        }
        buf = new_buf;
    }

    private void extractExtensionFields()
    {
        int idx = EF_INDEX;

        while(idx < this.buf.length)
        {
            NTSExtensionField ef = NTSExtensionField.fromBytes(this.buf, idx);
            idx += ef.getFieldLength();
            extensionFields.add(ef);
        }
    }

    public List<NTSExtensionField> getExtensionFields()
    {
        if(extensionFields.size() == 0 && buf.length > EF_INDEX)
        {
            extractExtensionFields();
        }

        return extensionFields;
    }

    public List<NTSExtensionField> getExtensionFields(final int type)
    {
        List<NTSExtensionField> res = new ArrayList<>();
        for(NTSExtensionField ef: getExtensionFields())
        {
            if(ef.fieldType.getValue()==type)
            {
                res.add(ef);
            }
        }
        return res;
    }

    /**
     * Compares this object against the specified object. The result is {@code true} if and only if the argument is not {@code null} and is a
     * <code>NtpV4Impl</code> object that contains the same values as this object.
     *
     * @param obj the object to compare with.
     * @return {@code true} if the objects are the same; {@code false} otherwise.
     * @since 3.4
     */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        final NtpV4Impl other = (NtpV4Impl) obj;
        return java.util.Arrays.equals(buf, other.buf);
    }


    /**
     * Returns details of NTP packet as a string.
     *
     * @return details of NTP packet as a string.
     */
    @Override
    public String toString() {
        String res =  "[" + "version:" + getVersion() + ", mode:" + getMode() + ", poll:" + getPoll() + ", precision:" + getPrecision() + ", delay:" + getRootDelay()
                + ", dispersion(ms):" + getRootDispersionInMillisDouble() + ", id:" + getReferenceIdString() + ", xmitTime:"
                + getTransmitTimeStamp().toDateString() ; //+ " ]";

        for(NTSExtensionField fld : extensionFields)
        {
            res += ", " + fld;
        }

        return res + " ]";

    }

}

