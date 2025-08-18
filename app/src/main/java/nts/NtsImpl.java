/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nts;

import nts.NTSExtensionFields.FieldType;
import nts.NTSExtensionFields.NTSExtensionField;

import org.cryptomator.siv.*;
//import org.cryptomator.siv.org.bouncycastle.util.Arrays;
import java.util.Arrays;
import java.io.IOException;

/**
 * Implements {@link NtsPacket} to convert Java objects to and from the Network Time Protocol (NTP) data message header format described in RFC-1305.
 */
public class NtsImpl extends NtpV4Impl implements NtsPacket {


    public int associatedDataLenght;
    public byte[] plaintext;
    public NTSExtensionField authAndEncEF;
    private byte[] ctrKey;
    private byte[] macKey;

    private static final SivMode AES_SIV = new SivMode();

    /** Creates a new instance of NtsImpl */
    public NtsImpl(byte []key) {
        ctrKey = new byte[16];
        macKey = new byte[16];
        System.arraycopy(key, 0, macKey, 0, 16);  // macKey are the first 16 bytes of the "concatenated" key
        System.arraycopy(key, 16, ctrKey, 0, 16);  // ctrKey are the last 16 bytes of the "concatenated" key
    }

    /**
     * Build an NTS packet
     * @param cookie The NTS cookie to use in the packet
     * @param num_cookies Number of cookies to request
     */
    public void buildRequest(final byte [] cookie, final int num_cookies)
    {
        super.buildRequest();

        // Calculate a unique identifier and add the Extension Field
        byte[] unique_identifier = new byte[32];
        new java.security.SecureRandom().nextBytes(unique_identifier);
        addUniqueIdentifierEF(unique_identifier);

        // Use one of the negotiated cookies
        addCookieEF(cookie);

        // Replace used cookies (try to maintain a backlog of 8)
        // The server will respond with one new cookie to replace
        // the cookie in the extension field above plus one extra
        // for each cookie placeholder, so we count from 0 to num_cookies-2
        // below
        for(int idx=0; idx < num_cookies - 1; ++idx)
        {
            addCookiePlaceholderEF(cookie);
        }

        /*
         * Prepare the authentication and encryption Extension Field
         * This is done here to avoid unnecessary delays in the time measurement the timestamping of the request packet.
         */
        prepareAuthAndEncEF();
        
    }

    /**
     * Adds a unique identifier extension field to the NTSv4 packet.
     * @param unique_identifier_body the unique identifier byte array, must be at least 32 bytes long.
     */
    public void addUniqueIdentifierEF(byte[] unique_identifier_body) {
        if (unique_identifier_body == null || unique_identifier_body.length < 32) {
            throw new IllegalArgumentException("unique_identifier_ef must be at least 32 bytes long");
        }
        addExtensionField(new NTSExtensionField(FieldType.UNIQUE_IDENTIFIER, unique_identifier_body));
    }

    /**
     * Adds a cookie extension field to the NTSv4 packet.
     *
     * @param cookie_body a cookie received from the NTS KE process or from a server response.
     */
    public void addCookieEF(byte[] cookie_body) {
        addExtensionField(new NTSExtensionField(FieldType.NTS_COOKIE, cookie_body));
    }

    /**
     * Adds a cookie placeholder extension filed to the NTSv4 packet
     * 
     * @param existing_cookie The cookie to be replaced
     */
    public void addCookiePlaceholderEF(byte []existing_cookie)
    {
        addExtensionField(new NTSExtensionField(FieldType.NTS_COOKIE_PLACEHOLDER, new byte[existing_cookie.length]));
    }

    /**
     * Prepare the authentication and encryption Extension Field body with the available information.
     * Ideally we should get the nonce length and ciphertext length from a table depending on the negotiated protocol.
     *
     * @return the body of the AuthAndEnc EF as bytearray.
     */
    private byte[] prepareAuthAndEncBody() {
        int nonceLength = 16;
        int ciphertextLength = 16;
        byte[] auth_and_enc_body = new byte[4 + nonceLength + ciphertextLength];
        auth_and_enc_body[0] = (byte) ((nonceLength >> 8) & 0xFF);
        auth_and_enc_body[1] = (byte) (nonceLength & 0xFF);
        auth_and_enc_body[2] = (byte) ((ciphertextLength >> 8) & 0xFF);
        auth_and_enc_body[3] = (byte) (ciphertextLength & 0xFF);
        return auth_and_enc_body;
    }


    /**
     * Constructs all the possible variables that will be used for the authentication and encryption extension field.
     * This is done here to avoid unnecessary delays in the time measurement after timestamping of the request packet.
     * This should be called after all the Extension Fields and other parameters have been added to the packet.
     */
    public void prepareAuthAndEncEF() {

        // Construct the NTSv4 packet and store the associated data length
        associatedDataLenght = buf.length;

        // Instantiate everything possible
        plaintext = "".getBytes();
        byte[] authAndEncBody = prepareAuthAndEncBody(); 
        authAndEncEF =new NTSExtensionField(FieldType.NTS_AUTH_AND_ENC, authAndEncBody); 
        addExtensionField(authAndEncEF);
    }

    /**
     * Creates the AuthAndEnc EF with the given keys and nonce.
     * This is done after the NTP packet has been timestamped. Must be called after prepareAuthAndEncEF() has been called.
     *
     * @param nonce  the nonce to be used for encryption
     */
    public void createAuthAndEncEF(byte[] nonce) {
        
        byte[] ciphertext = AES_SIV.encrypt(ctrKey, macKey, plaintext, Arrays.copyOfRange(buf, 0, associatedDataLenght), nonce);
        authAndEncEF.replaceBody(nonce, 4);
        authAndEncEF.replaceBody(ciphertext, 4 + nonce.length);

        System.arraycopy(authAndEncEF.toByteArray(), 0, buf, associatedDataLenght, authAndEncEF.getFieldLength());
    }

    /**
     * Creates the AuthAndEnc EF with the given keys and a random nonce.
     * This is done after the NTP packet has been timestamped. Must be called after prepareAuthAndEncEF() has been called.
     *
     */
    public void createAuthAndEncEF()
    {
        byte[] nonce = new byte[16];
        new java.security.SecureRandom().nextBytes(nonce);
        createAuthAndEncEF(nonce);
    }

    /**
     * @return 2 bytes as 16-bit int
     */
    private int getShort(final byte[] buf, final int index) {
        return ui(buf[index]) << 8 | ui(buf[index + 1]);
    }

    private void extractExtensionFieldsFrom(byte [] src, int idx)
    {
        while(idx < src.length)
        {
            NTSExtensionField ef = NTSExtensionField.fromBytes(src, idx);
            if(ef.fieldType == FieldType.NTS_AUTH_AND_ENC)
            {
                associatedDataLenght = idx;
                authAndEncEF = ef;
            }
            idx += ef.getFieldLength();
            extensionFields.add(ef);
        }

    }

    private void extractExtensionFields()
    {
        int idx = 48;
        associatedDataLenght = -1;
        authAndEncEF = null;
        extractExtensionFieldsFrom(buf, idx);
    }

    /**
     * Decrypt and verify a received NTS packet
     *
     */
    public byte [] decryptAndVerify() throws AuthenticationFailureException
    {
        if(associatedDataLenght == -1 || authAndEncEF == null)
        {
            extractExtensionFields();
            if(associatedDataLenght == -1 || authAndEncEF ==null)
            {
                throw new RuntimeException("No authentication information found");
            }
        }

        int nonce_len = getShort(authAndEncEF.body, 0); 
        int ct_len = getShort(authAndEncEF.body, 2);
        byte [] nonce = Arrays.copyOfRange(authAndEncEF.body, 4, 4+nonce_len);
        byte [] ct = Arrays.copyOfRange(authAndEncEF.body, 4+nonce_len, 4+nonce_len+ct_len);

        byte [] ad = Arrays.copyOfRange(buf, 0, associatedDataLenght);

        byte [] pt;
        try
        {
            pt = AES_SIV.decrypt(ctrKey, macKey, ct, ad, nonce);
        }
        catch(final UnauthenticCiphertextException e)
        {
            throw new AuthenticationFailureException(e.getMessage());
        }
        catch(final Exception e)
        {
            throw new RuntimeException(e.getMessage());
        }

        extractExtensionFieldsFrom(pt, 0);

        return pt;
    }

    /**
     * Validate a response packet given a request packet
     * 
     * @param req - The request packet
     * 
     * @throws IOException - On failure
     */
    @Override
    public void validate(NtsPacket req) throws IOException, NtsNakException, AuthenticationFailureException
    {
        if(getStratum() == 0 && getReferenceIdString() == "NTSN")
        {
            throw new NtsNakException();
        }
        super.validate((NtpV3Packet) req);

        decryptAndVerify();

    }

}

