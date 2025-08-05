package nts;

import java.security.Security;

import javax.net.ssl.*;
import org.conscrypt.Conscrypt;

import nts.NTSKERecords.Constants.AEADAlgorithms;
import nts.NTSKERecords.Constants.NTSNextProtocols;
import nts.NTSKERecords.NTSKERecordFactory;


public class NTSKEHandshake {

    public static String LABEL = "EXPORTER-network-time-security";
    public static byte[] PROTO_ID_NTPV4 = {0x00, 0x00};
    public static byte[] AEAD_AES_SIV_CMAC_256 = {0x00, (byte) 0x0F};
    public static byte C2S_CONTEXT = 0x00;
    public static byte S2C_CONTEXT = 0x01;
    private SSLSocketFactory factory;

    public NTSKEHandshake() {
        // Create a TLSv1.3 socket using Conscrypt to have access to exportKeyingMaterial
        try {
            Security.insertProviderAt(Conscrypt.newProvider(), 1);
            SSLContext context = SSLContext.getInstance("TLSv1.3", "Conscrypt");
            context.init(null, null, null);
            factory = context.getSocketFactory();
        } catch (Exception e) {
            e.printStackTrace();
        }
        
    }

    private static void printSession(SSLSession session) {
        try {
            System.out.println("Protocol: " + session.getProtocol());
            System.out.println("Cipher Suite: " + session.getCipherSuite());
            System.out.println("Peer Host: " + session.getPeerHost());
            System.out.println("Peer Port: " + session.getPeerPort());
            //System.out.println(session.getPeerCertificates()[0]);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] getKeyExpansionContext(byte CS2orS2C) {
        byte[] key_extraction_context = new byte[5];
        System.arraycopy(PROTO_ID_NTPV4, 0, key_extraction_context, 0, 2);
        System.arraycopy(AEAD_AES_SIV_CMAC_256, 0, key_extraction_context, 2, 2);
        key_extraction_context[4] = CS2orS2C;
        return key_extraction_context;
    }

    public NTSConfig doHandshake(String host, int port) {

        try {
            SSLSocket socket = (SSLSocket) factory.createSocket(host, port);

            // Must be TLSv1.3 and ALPN Offer "ntske/1"
            SSLParameters params = socket.getSSLParameters();
            params.setProtocols(new String[] { "TLSv1.3" });
            params.setApplicationProtocols(new String[] { "ntske/1" });
            socket.setSSLParameters(params);

            socket.startHandshake();
            //printSession(socket.getSession());

            // Create NTSKE Client Message
            NTSKEMessage NtsKeClientMessage = new NTSKEMessage();
            NtsKeClientMessage.addNTSKERecord(NTSKERecordFactory.getNTSNextProtocolNegotiationRecord(NTSNextProtocols.NTPv4));
            NtsKeClientMessage.addNTSKERecord(NTSKERecordFactory.getAEADAlgorithmNegotiationRecord(AEADAlgorithms.AEAD_AES_SIV_CMAC_256));
            NtsKeClientMessage.addNTSKERecord(NTSKERecordFactory.getEndOfMessageRecord());

            //System.out.println("\nNTSKE Client Message:");
            //System.out.println(NtsKeClientMessage);

            socket.getOutputStream().write(NtsKeClientMessage.toBytes());
            socket.getOutputStream().flush();

            // Read Response
            byte[] response = new byte[1024];
            int bytesRead = socket.getInputStream().read(response);

            // Create NTSKE Response Message
            NTSKEMessage NTSKEResponseMessage = NTSKEMessage.parseNTSKERawMessage(response, bytesRead);
            //System.out.println("\nNTSKE Server Message:");
            //System.out.println(NTSKEResponseMessage);

            // Derive client and server keys from TLS handshake
            byte[] context_c2s = getKeyExpansionContext(C2S_CONTEXT);
            byte[] context_s2c = getKeyExpansionContext(S2C_CONTEXT);

            byte[] c2s_key = Conscrypt.exportKeyingMaterial(socket, LABEL, context_c2s, 32);
            byte[] s2c_key = Conscrypt.exportKeyingMaterial(socket, LABEL, context_s2c, 32);
            
            socket.close();

            NTSConfig ntsConfig = NTSKEResponseMessage.parseResponse(host, port);
            ntsConfig.C2SKey = c2s_key;
            ntsConfig.S2CKey = s2c_key;

            return ntsConfig;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {

        String host = "ntppool1.time.nl";
        int port = 4460;

        NTSKEHandshake tlsHandshake = new NTSKEHandshake();
        NTSConfig ntsConfig = tlsHandshake.doHandshake(host, port);
        System.out.println("Result: " + ntsConfig);

    }


}