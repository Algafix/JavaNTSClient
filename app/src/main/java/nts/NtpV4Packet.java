package nts;

import nts.NTSExtensionFields.NTSExtensionField;

import java.util.List;

public interface NtpV4Packet extends NtpV3Packet {
   
    public void addExtensionField(NTSExtensionField field);
    public void addExtensionFields(List<NTSExtensionField> fields);
    public List<NTSExtensionField> getExtensionFields();
    public List<NTSExtensionField> getExtensionFields(final int type);
}
