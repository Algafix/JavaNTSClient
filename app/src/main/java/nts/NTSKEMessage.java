package nts;

import java.util.ArrayList;
import java.util.List;

import nts.NTSKERecords.*;

public class NTSKEMessage {

    private List<NTSKERecord> NTSKERecords = new ArrayList<>();
    private int totalLength = 0;

    public void addNTSKERecord(NTSKERecord record) {
        NTSKERecords.add(record);
        totalLength += record.toBytes().length;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (NTSKERecord record : NTSKERecords) {
            sb.append(record.toString() + '\n');
        }
        sb.deleteCharAt(sb.length()-1);
        return sb.toString();
    }

    public byte[] toBytes() {
        byte[] result = new byte[totalLength];
        int pos = 0;
        for (NTSKERecord record : NTSKERecords) {
            byte[] recBytes = record.toBytes();
            System.arraycopy(recBytes, 0, result, pos, recBytes.length);
            pos += recBytes.length;
        }
        return result;
    }

    public String toByteString() {
        StringBuilder sb = new StringBuilder();
        for (byte b : toBytes()) {
            sb.append(String.format("%02X ", b));
        }
        sb.append('\n');
        return sb.toString();
    }

    public static NTSKEMessage parseNTSKERawMessage(byte [] raw_message, int size){
        int offset = 0;
        NTSKEMessage message = new NTSKEMessage();
        while (size - offset >= 4) {
            int body_length = ((raw_message[offset+2] & 0xFF) << 8) | (raw_message[offset+3] & 0xFF);
            byte[] raw_ntskeRecord = new byte[4+body_length];
            System.arraycopy(raw_message, offset, raw_ntskeRecord, 0, 4 + body_length);
            NTSKERecord record = NTSKERecordFactory.parseRecord(raw_ntskeRecord);
            message.addNTSKERecord(record);

            offset += 4 + body_length;
            if (offset > size) break;
        }
        return message;
    }

    /**
     * Parse the response from the NTS KE Server and extract the NTSConfig.
     * TO DO: Check that there is only one of NTSNPN, AEADAN, and that EoM is the last record.
     * @param KE_host host of the NTS KE Server, will be used as NTP host if the NTPv4ServerNegotiation record is not present.
     * @param KE_port port of the NTS KE Server, will be used as NTP port if the NTPv4PortNegotiation record is not present.
     * @throws IllegalStateException if the NTS KE Server communicated an error or if no cookies were received.
     * @throws IllegalArgumentException if the response has an Error or Warning record.
     * @return
     */
    public NTSConfig parseResponse(String KE_host, int KE_port) {
        NTSConfig config = new NTSConfig();
        config.host = KE_host;
        config.port = KE_port;

        for (NTSKERecord record : NTSKERecords) {
            switch (record.recordType) {
                case Error:
                    Constants.ErrorCodes errorCode = Constants.ErrorCodes.fromBytes(record.recordBody);
                    throw new IllegalStateException("The NTS KE Server communicated an error: " + errorCode);
                case Warning:
                    int warningCode = record.recordBody[0] << 8 | (record.recordBody[1] & 0xFF);
                    throw new IllegalStateException("The NTS KE Server communicated an error: " + warningCode);
                case NTSNextProtocolNegotiation:
                    config.NTSProtocol = ((NTSNextProtocolNegotiation) record).NTSProtocol;
                    break;
                case AEADAlgorithmNegotiation: 
                    config.AEADAlgorithm = ((AEADAlgorithmNegotiation) record).algorithms[0];
                    break;
                case NewCookieForNTPv4:
                    config.cookies.add(record.recordBody);
                    break;
                case NTPv4ServerNegotiation:
                    config.host = ((NTPv4ServerNegotiation) record).NTPv4Server;
                    break;
                case NTPv4PortNegotiation:
                    config.port = ((NTPv4PortNegotiation) record).NTPv4Port;
                    break;
                default:
                    break;
            }
        }

        if (config.cookies.size() < 1) {
            throw new IllegalStateException("No cookies received from NTS KE Server.");
        }

        return config;
    }
}
