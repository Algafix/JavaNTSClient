package nts;

public class NTSPeer {
    public String KEHost;
    public int KEPort = 4460; // Default port for KE
    private NTSKEHandshake tlsHandshake = new NTSKEHandshake();
    public NTSConfig ntsConfig;

    public NTSPeer(String KEHost) {
        this.KEHost = KEHost;
        doHandshake();
    }

    public void doHandshake() {
        ntsConfig = tlsHandshake.doHandshake(KEHost, KEPort);
    }

    public NTSPeer() {
        // Default constructor
    }

}
