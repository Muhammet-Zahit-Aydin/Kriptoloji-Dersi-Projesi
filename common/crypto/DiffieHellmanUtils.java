package common.crypto;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class DiffieHellmanUtils {

    // 2048-bit Diffie-Hellman anahtar çifti (Public / Private Key) üretir.
    public static KeyPair generateDHKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(2048);
        return keyPairGen.generateKeyPair();
    }

    //Kendi Private Key'imiz ve karşı tarafın Public Key'i ile ortak bir sır (shared secret) hesaplar.
    public static byte[] computeSharedSecret(PrivateKey myPrivateKey, PublicKey otherPublicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(myPrivateKey);
        keyAgreement.doPhase(otherPublicKey, true);
        return keyAgreement.generateSecret();
    }

    // Ortak sırdan (shared secret) AES-128 bit (16 byte) session key türetir.
    // Güvenlik için shared secret doğrudan kullanılmaz, SHA-256'dan geçirilip ilk 16 byte'ı alınır.
    public static SecretKeySpec deriveAes128Key(byte[] sharedSecret) throws NoSuchAlgorithmException {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update(sharedSecret);
        byte[] derivedKey = hash.digest();
        
        // AES-128 için ilk 16 byte'ı (128 bit) alıyoruz
        byte[] aesKeyBytes = Arrays.copyOfRange(derivedKey, 0, 16);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    // Ağ üzerinden gelen byte dizisini (encoded public key) PublicKey nesnesine çevirir.
    public static PublicKey getPublicKeyFromBytes(byte[] pubKeyBytes) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyBytes);
        return keyFactory.generatePublic(x509KeySpec);
    }
}