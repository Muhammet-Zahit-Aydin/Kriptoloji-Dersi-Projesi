package common.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Sunucu ve iki istemcinin ortak DH-2048 parametreleri ve anahtar türetmesi. */
public final class DiffieHellmanUtils {
    // RFC 3526, bölüm 3: MODP grup 14; p 2048 bit, üreteç g = 2.
    private static final BigInteger PRIME = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            + "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger GENERATOR = BigInteger.TWO;
    private static final BigInteger SUBGROUP_ORDER = PRIME.subtract(BigInteger.ONE).divide(BigInteger.TWO);

    private DiffieHellmanUtils() { }

    public static KeyPair generateDHKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");
        generator.initialize(new DHParameterSpec(PRIME, GENERATOR));
        return generator.generateKeyPair();
    }

    /** Özel anahtar yerelde kalır; yalnızca doğrulanmış karşı açık değer kullanılır. */
    public static byte[] computeSharedSecret(PrivateKey privateKey, PublicKey publicKey)
            throws GeneralSecurityException {
        validatePublicKey(publicKey);
        KeyAgreement agreement = KeyAgreement.getInstance("DH");
        agreement.init(privateKey);
        agreement.doPhase(publicKey, true);
        return agreement.generateSecret();
    }

    /** Önceki ortak sözleşme korunur: SHA-256(sharedSecret) çıktısının ilk 16 byte'ı. */
    public static SecretKeySpec deriveAes128Key(byte[] sharedSecret) throws NoSuchAlgorithmException {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(sharedSecret);
        byte[] key = Arrays.copyOf(hash, 16);
        try {
            return new SecretKeySpec(key, "AES");
        } finally {
            Arrays.fill(hash, (byte) 0);
            Arrays.fill(key, (byte) 0);
        }
    }

    /** Ağda açık anahtar X.509 SubjectPublicKeyInfo DER biçiminde taşınır. */
    public static PublicKey getPublicKeyFromBytes(byte[] encoded) throws GeneralSecurityException {
        PublicKey publicKey = KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(encoded));
        validatePublicKey(publicKey);
        return publicKey;
    }

    private static void validatePublicKey(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof DHPublicKey dhKey)
                || !PRIME.equals(dhKey.getParams().getP())
                || !GENERATOR.equals(dhKey.getParams().getG())) {
            throw new InvalidKeyException("DH anahtarı ortak 2048 bit gruba ait değil.");
        }
        BigInteger value = dhKey.getY();
        if (value.compareTo(BigInteger.TWO) < 0
                || value.compareTo(PRIME.subtract(BigInteger.TWO)) > 0
                || !value.modPow(SUBGROUP_ORDER, PRIME).equals(BigInteger.ONE)) {
            throw new InvalidKeyException("DH açık değeri geçersiz.");
        }
    }
}
