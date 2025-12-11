import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.daead.AesSivParameters;
import com.google.crypto.tink.daead.subtle.DeterministicAeads;
import com.google.crypto.tink.subtle.AesSiv;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;


public class TinkSivTest {

    public static void main(String[] args) throws Exception {
        AesSivTest1();
    }

    public static void AesSivTest2() throws Exception {
        AesSivParameters parameters =
            AesSivParameters.builder()
                .setKeySizeBytes(64)
                .setVariant(AesSivParameters.Variant.NO_PREFIX)
                .build();
        SecretBytes keyBytes =
            SecretBytes.copyFrom(
                    Hex.decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                    + "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"),
                InsecureSecretKeyAccess.get());

        AesSivKey key = AesSivKey.builder().setParameters(parameters).setKeyBytes(keyBytes).build();
        byte[] plaintext = Hex.decode("Hello World");
        byte[] aad = Hex.decode("FF");
        byte[] ciphertext = Hex.decode("1BC49C6A894EF5744A0A01D46608CBCC");

        DeterministicAeads daead = AesSiv.create(key);

        byte[] encrypted_one_ad = daead.encryptDeterministically(plaintext, aad);
        System.out.println("Encrypted: " + Hex.encode(encrypted_one_ad) + " expected: " + Hex.encode(ciphertext));
        byte[] decrypted_one_ad = daead.decryptDeterministically(encrypted_one_ad, aad);
        System.out.println("Decrypted: " + Hex.encode(decrypted_one_ad) + " expected: " + Hex.encode(plaintext));

        // also test the DeterministicAeads interface
        byte[] encrypted_multiple_aad = daead.encryptDeterministicallyWithAssociatedDatas(plaintext, new byte[][] {aad});
        System.out.println("Encrypted with multiple AAD: " + Hex.encode(encrypted_multiple_aad) + " expected: " + Hex.encode(ciphertext));
        byte[] decrypted_multiple_aad = daead.decryptDeterministicallyWithAssociatedDatas(encrypted_multiple_aad, new byte[][] {aad});
        System.out.println("Decrypted with multiple AAD: " + Hex.encode(decrypted_multiple_aad) + " expected: " + Hex.encode(plaintext));
    }


    public static void AesSivTest1() throws Exception {
        AesSivParameters parameters =
            AesSivParameters.builder()
                .setKeySizeBytes(32)
                .setVariant(AesSivParameters.Variant.NO_PREFIX)
                .build();
        
        // Note that in this case ctr and mac keys are not swapped like with cryptomator
        byte[] ctrKey = "5c75f1d00a619377".getBytes();
        byte[] macKey = "0405cf87e5bc49e2".getBytes();
        byte[] keyRaw = new byte[ctrKey.length + macKey.length];
        System.arraycopy(ctrKey, 0, keyRaw, 0, ctrKey.length);
        System.arraycopy(macKey, 0, keyRaw, ctrKey.length, macKey.length);
        
        SecretBytes keyBytes =
            SecretBytes.copyFrom(
                keyRaw,
                InsecureSecretKeyAccess.get());

        AesSivKey key = AesSivKey.builder().setParameters(parameters).setKeyBytes(keyBytes).build();
        byte[] plaintext = "hello world".getBytes();
        byte[] nonce = new byte[16];
        byte[] aad = new byte[32];
        java.util.Arrays.fill(aad, (byte) 0x43);
        java.util.Arrays.fill(nonce, (byte) 0x44);

        DeterministicAeads daead = AesSiv.create(key);

        // Test the DeterministicAeads interface
        System.out.println("key: " + Hex.encode(keyRaw));
        System.out.println("nonce: " + Hex.encode(nonce));
        System.out.println("asso_data: " + Hex.encode(aad));

        byte[] encrypted_multiple_aad = daead.encryptDeterministicallyWithAssociatedDatas(plaintext, new byte[][] {aad, nonce});
        System.out.println("Encrypted: " + Hex.encode(encrypted_multiple_aad));
        byte[] decrypted_multiple_aad = daead.decryptDeterministicallyWithAssociatedDatas(encrypted_multiple_aad, new byte[][] {aad, nonce});
        System.out.println("Decrypted: " + Hex.encode(decrypted_multiple_aad) + " expected: " + Hex.encode(plaintext));
    }

}
