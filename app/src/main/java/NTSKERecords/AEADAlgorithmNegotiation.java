package NTSKERecords;

public class AEADAlgorithmNegotiation extends NTSKERecord {

    public Constants.AEADAlgorithms[] algorithms;

    /**
     * Constructor for AEADAlgorithmNegotiation record with default values.
     */
    public AEADAlgorithmNegotiation(Constants.AEADAlgorithms[] algorithms) {
        super(1, NTSKERecordType.AEADAlgorithmNegotiation.getValue(), algorithms.length * 2, bodyParameterToByteArray(algorithms));
        this.algorithms = algorithms;
    }

    private static byte[] bodyParameterToByteArray(Constants.AEADAlgorithms[] algorithms) {
        byte[] bodyBytes = new byte[algorithms.length * 2];
        for (int i = 0; i < algorithms.length; i++) {
            System.arraycopy(algorithms[i].getBytesValue(), 0, bodyBytes, i * 2, 2);
        }
        return bodyBytes;
    }

    private static Constants.AEADAlgorithms[] byteArrayToAlgorithms(byte[] body) {
        if (body.length % 2 != 0) {
            throw new IllegalArgumentException("Body length must be a multiple of 2 for AEADAlgorithmNegotiation record.");
        }
        Constants.AEADAlgorithms[] algorithms = new Constants.AEADAlgorithms[body.length / 2];
        for (int i = 0; i < algorithms.length; i++) {
            algorithms[i] = Constants.AEADAlgorithms.fromBytes(new byte[]{body[i * 2], body[i * 2 + 1]});
        }
        return algorithms;
    }

    /**
     * Constructor for AEADAlgorithmNegotiation record from a raw byte array. Verifies that the values are correct.
     * @param rawRecord the raw byte array containing the record data.
     */
    public AEADAlgorithmNegotiation(byte[] rawRecord) {
        super(rawRecord);

        if (recordType != NTSKERecordType.AEADAlgorithmNegotiation) {
            throw new IllegalArgumentException("Record type must be AEADAlgorithmNegotiation.");
        }
        if ((bodyLength == 0) || (recordBody == null)) {
            throw new IllegalArgumentException("No record body. AEAD Algorithms requested are unsuported by the server.");
        }

        algorithms = byteArrayToAlgorithms(recordBody);

    }
    
}
