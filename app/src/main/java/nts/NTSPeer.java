package nts;

public class NTSPeer {
    public String KEHost;
    public int KEPort = 4460; // Default port for KE
    public NTSConfig ntsConfig;

    public NTSPeer(String KEHost, int KEPort, NTSConfig ntsConfig) {
        this.KEHost = KEHost;
        this.KEPort = KEPort;
        this.ntsConfig = ntsConfig;
    }

    public NTSPeer(String KEHost) {
        this.KEHost = KEHost;
    }

    public NTSPeer() {
        // Default constructor
    }

}
