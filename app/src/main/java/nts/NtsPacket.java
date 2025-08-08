package nts;

public interface NtsPacket extends NtpV4Packet {
    /**
     * Adds a unique identifier extension field to the NTSv4 packet.
     * @param unique_identifier_body the unique identifier byte array, must be at least 32 bytes long.
     */
    public void addUniqueIdentifierEF(byte[] unique_identifier_body);

    /**
     * Adds a cookie extension field to the NTSv4 packet.
     *
     * @param cookie_body a cookie received from the NTS KE process or from a server response.
     */
    public void addCookieEF(byte[] cookie_body);

    /**
     * Adds a cookie placeholder extension filed to the NTSv4 packet
     * 
     * @param existing_cookie The cookie to be replaced
     */
    public void addCookiePlaceholderEF(byte []existing_cookie);

    /**
     * Constructs all the possible variables that will be used for the authentication and encryption extension field.
     * This is done here to avoid unnecessary delays in the time measurement after timestamping of the request packet.
     * This should be called after all the Extension Fields and other parameters have been added to the packet.
     */
    public void prepareAuthAndEncEF();

    /**
     * Creates the AuthAndEnc EF with the given keys and nonce.
     * This is done after the NTP packet has been timestamped. Must be called after prepareAuthAndEncEF() has been called.
     *
     * @param ctrKey First half of the AES_SIV Key
     * @param macKey Second half of the AES_SIV Key
     * @param nonce  the nonce to be used for encryption
     */
    public void createAuthAndEncEF(byte[] ctrKey, byte[] macKey, byte[] nonce);

    /**
     * Decrypt and verify a received NTS packet
     *
     * @param ctrKey First half of the AES_SIV Key
     * @param macKey Second half of the AES_SIV Key
     */
    public byte [] decryptAndVerify(byte [] ctrKey, byte []macKey) throws AuthenticationFailureException;
}
