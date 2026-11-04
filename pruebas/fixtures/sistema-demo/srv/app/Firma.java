import java.security.*;
import javax.crypto.*;

public class Firma {
    // MessageDigest.getInstance("MD5") quedó fuera.
    byte[] resumen(byte[] d) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(d);
    }
    Cipher cifrador() throws Exception {
        return Cipher.getInstance("AES");
    }
    KeyPair par() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }
    KeyPair kem() throws Exception {
        return KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair();
    }
    Signature firma() throws Exception {
        return Signature.getInstance("SHA256withRSA");
    }
}
