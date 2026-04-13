import java.security.*;
import javax.crypto.*;

public class CryptoExample {
    public static void main(String[] args) throws Exception {
        // RSA key generation
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        // RSA cipher
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");

        // ECDSA signature
        Signature sig = Signature.getInstance("SHA256withECDSA");

        // DES cipher (weak)
        Cipher desCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");

        // MD5 hash (weak)
        MessageDigest md = MessageDigest.getInstance("MD5");
    }
}
