
import org.cryptomator.siv.*;

public class AesSivTest {
    private static final SivMode AES_SIV = new SivMode();

    public static String bytes2hex(byte[] byteArray) {
        StringBuilder sb = new StringBuilder();
        for (byte b : byteArray) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) {

        // Same results as in python
        /*
            from Crypto.Cipher import AES

            key = b'5c75f1d00a6193770405cf87e5bc49e2'
            nonce = b'D'*16
            asso_data = b'C'*32
            plaintext = b'hello world'
            aead = AES.new(key, AES.MODE_SIV, nonce)
            aead.update(asso_data)
            cipher, tag = aead.encrypt_and_digest(plaintext)

            print(cipher.hex())  # e7886264d37ff291a7760d
            print(tag.hex())     # 7bdc2b8602feee2da9b8acd676f06d52
        */

        // macKey are the first 16 bytes of the "concatenated" key
        // ctrKey are the last 16 bytes of the "concatenated" key
        byte[] ctrKey = "0405cf87e5bc49e2".getBytes();
        byte[] macKey = "5c75f1d00a619377".getBytes();
        byte[] nonce = new byte[16];
        byte[] asso_data = new byte[32];
        java.util.Arrays.fill(asso_data, (byte) 0x43);
        java.util.Arrays.fill(nonce, (byte) 0x44);
        System.out.println("key: " + bytes2hex(ctrKey) + " " + bytes2hex(macKey));
        System.out.println("nonce: " + bytes2hex(nonce));
        System.out.println("asso_data: " + bytes2hex(asso_data));

        try {
            byte[] plaintext = "hello world".getBytes();
            System.out.println(bytes2hex(plaintext));
            byte[] encrypted = AES_SIV.encrypt(ctrKey, macKey, plaintext, asso_data, nonce);
            System.out.println(bytes2hex(encrypted));
            byte[] decrypted = AES_SIV.decrypt(ctrKey, macKey, encrypted, asso_data, nonce);
            System.out.println(bytes2hex(decrypted));

        } catch (Exception e) {
            System.err.println(e);
        }
    }

}

