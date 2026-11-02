// common/crypto/RsaCryptoService.java
package common.crypto;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RsaCryptoService {
    private static final String ALGORITHM = "RSA";
    private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final int KEY_SIZE = 2048;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public void generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(KEY_SIZE);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    // Public key'i X.509 formatında Base64 string olarak dışa aktar
    public String getPublicKeyAsBase64() {
        return Base64.getEncoder().encodeToString(this.publicKey.getEncoded());
    }

    // Gelen Base64 string'i Public Key objesine dönüştür
    public static PublicKey getPublicKeyFromBase64(String base64Key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePublic(spec);
    }

    // İstemcide AES anahtarını şifrelemek için
    public static byte[] encryptAesKey(byte[] aesKey, PublicKey pubKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return cipher.doFinal(aesKey);
    }

    // Sunucuda gelen AES anahtarını çözmek için
    public byte[] decryptAesKey(byte[] encryptedAesKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        return cipher.doFinal(encryptedAesKey);
    }
}