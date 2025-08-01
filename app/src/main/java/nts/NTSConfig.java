package nts;

import java.util.ArrayList;
import java.util.List;

import NTSKERecords.*;

public class NTSConfig {
    public Constants.NTSNextProtocols NTSProtocol;
    public Constants.AEADAlgorithms AEADAlgorithm;
    public List<byte[]> cookies = new ArrayList<>();
    public String host;
    public int port;
    public byte[] C2SKey;
    public byte[] S2CKey;

    public NTSConfig(Constants.NTSNextProtocols NTSProtocol, Constants.AEADAlgorithms AEADAlgorithm, List<byte[]> cookies, String host, int port, byte[] C2SKey, byte[] S2CKey) {
        this.NTSProtocol = NTSProtocol;
        this.AEADAlgorithm = AEADAlgorithm;
        this.cookies = cookies;
        this.host = host;
        this.port = port;
        this.C2SKey = C2SKey;
        this.S2CKey = S2CKey;
    }

    public NTSConfig() {
        // Default constructor
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("NTSConfig {")
          .append("\n  NTSProtocol: ").append(NTSProtocol)
          .append("\n  AEADAlgorithm: ").append(AEADAlgorithm)
          .append("\n  cookies: [");
        if (cookies != null) {
            for (int i = 0; i < cookies.size(); i++) {
                sb.append(bytesToHex(cookies.get(i)));
                if (i < cookies.size() - 1) sb.append(", ");
            }
        }
        sb.append("]")
          .append("\n  host: ").append(host)
          .append("\n  port: ").append(port)
          .append("\n  C2SKey: ").append(bytesToHex(C2SKey))
          .append("\n  S2CKey: ").append(bytesToHex(S2CKey))
          .append("\n}");
        return sb.toString();
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

}
