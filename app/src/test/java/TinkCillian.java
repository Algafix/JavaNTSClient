
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.daead.DeterministicAeadConfig;
import com.google.crypto.tink.daead.subtle.DeterministicAeads;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.daead.AesSivParameters;
import com.google.crypto.tink.subtle.AesSiv;
import com.google.common.primitives.Bytes;
import com.google.crypto.tink.util.SecretBytes;

import java.security.GeneralSecurityException;


class AesSivRawKeyReader 
{
    private final AesSivParameters aesSivParameters;

    public AesSivRawKeyReader() throws GeneralSecurityException
    {
        aesSivParameters = AesSivParameters.builder()
                .setVariant(AesSivParameters.Variant.NO_PREFIX)
                .setKeySizeBytes(32)
                .build();
    }

    public AesSivKey read(byte [] raw) throws GeneralSecurityException
    {
        return AesSivKey.builder()
            .setParameters(aesSivParameters)
            .setKeyBytes(SecretBytes.copyFrom(raw, InsecureSecretKeyAccess.get()))
            .build();
    }
};

public class TinkCillian {

    public static String bytes2hex(byte[] byteArray) {
        StringBuilder sb = new StringBuilder();
        for (byte b : byteArray) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    public static byte[] hex2bytes(String s)
    {
        int strlen = s.length();
        int bytelen = strlen/2;
        byte[] result = new byte[bytelen];
        for(int ii=0; ii < strlen; ii+=2)
        {
            result[ii/2] = (byte)((Character.digit(s.charAt(ii), 16)<<4) + Character.digit(s.charAt(ii+1), 16));
        }
        return result;
    }

    public static void main(String[] args) {


        // macKey are the first 32 bytes of the "concatenated" key
        // ctrKey are the last 32 bytes of the "concatenated" key
        byte[] ctrKey = new byte[16];
        byte[] macKey = new byte[16];
        byte[] nonce = new byte[16];
        byte[] asso_data = new byte[32];
        java.util.Arrays.fill(ctrKey, (byte) 'A');
        java.util.Arrays.fill(macKey, (byte) 'B');
        java.util.Arrays.fill(asso_data, (byte) 'C');
        java.util.Arrays.fill(nonce, (byte) 'D');
        byte[] fullKey = Bytes.concat(macKey, ctrKey);
        byte[] plaintext = "Hello World".getBytes();
        byte[] ciphertext_expected = hex2bytes("e1f5fbab85baa847748244");
        byte[] tag_expected = hex2bytes("51c5a8ac7cb3b687a233a864a8eb172a");
        byte [] encrypted_expected = Bytes.concat(tag_expected, ciphertext_expected);
        System.out.println("key: " + bytes2hex(fullKey));
        System.out.println("nonce: " + bytes2hex(nonce));
        System.out.println("asso_data: " + bytes2hex(asso_data));

        try {
            DeterministicAeadConfig.register();
            AesSivRawKeyReader reader = new AesSivRawKeyReader();

            DeterministicAeads daed = AesSiv.create(reader.read(fullKey));

            System.out.println(bytes2hex(plaintext));
            byte[] encrypted = daed.encryptDeterministicallyWithAssociatedDatas(plaintext, asso_data, nonce);
            System.out.println(bytes2hex(encrypted));
            byte[] decrypted = daed.decryptDeterministicallyWithAssociatedDatas(encrypted, asso_data, nonce);
            System.out.println(bytes2hex(decrypted));
            System.out.println(bytes2hex(encrypted_expected));
            assert(java.util.Arrays.equals(encrypted, encrypted_expected));

        } catch (Exception e) {
            System.err.println(e);
        }
    }

}



