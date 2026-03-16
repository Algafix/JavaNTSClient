import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.daead.AesSivParameters;
import com.google.crypto.tink.daead.subtle.DeterministicAeads;
import com.google.crypto.tink.subtle.AesSiv;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;


public class TinkSivTest {

    @Test
    public void AesSivTest1() throws Exception {
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

        assertArrayEquals(plaintext, decrypted_multiple_aad);

    }

}
