package common.crypto;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

/** İki istemcinin ortak kullanabileceği P-256 ECDH ve AES-128 türetme işlemleri. */
public final class EcdhUtils {
    public static final String CURVE_NAME = "secp256r1";
    private static final int SHARED_SECRET_BYTES = 32;
    private static final int AES_KEY_BYTES = 16;

    private EcdhUtils() { }

    /** Her çağrı yeni bir açık/özel anahtar çifti üretir. */
    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(CURVE_NAME));
        return generator.generateKeyPair();
    }

    /** Karşı taraftan gelen X.509 SubjectPublicKeyInfo DER açık anahtarını doğrular. */
    public static PublicKey getPublicKeyFromBytes(byte[] encoded) throws GeneralSecurityException {
        if (encoded == null || encoded.length == 0) {
            throw new InvalidKeyException("ECDH açık anahtarı boş olamaz.");
        }

        PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(encoded));
        validatePublicKey(publicKey);
        return publicKey;
    }

    /** Kendi özel anahtarı ve karşı tarafın açık anahtarıyla ortak sır hesaplanır. */
    public static byte[] computeSharedSecret(PrivateKey privateKey, PublicKey peerPublicKey)
            throws GeneralSecurityException {
        if (!(privateKey instanceof ECPrivateKey ecPrivateKey)) {
            throw new InvalidKeyException("ECDH için EC özel anahtarı gerekli.");
        }
        validateParameters(ecPrivateKey.getParams());
        validatePublicKey(peerPublicKey);

        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(privateKey);
        agreement.doPhase(peerPublicKey, true);
        return agreement.generateSecret();
    }

    /** Projedeki DH sözleşmesiyle aynı türetme: SHA-256(ortak sır), ilk 16 byte. */
    public static SecretKeySpec deriveAes128Key(byte[] sharedSecret) throws GeneralSecurityException {
        if (sharedSecret == null || sharedSecret.length != SHARED_SECRET_BYTES) {
            throw new InvalidKeyException("P-256 ortak sırrı 32 byte olmalı.");
        }

        byte[] hash = MessageDigest.getInstance("SHA-256").digest(sharedSecret);
        byte[] key = Arrays.copyOf(hash, AES_KEY_BYTES);
        try {
            return new SecretKeySpec(key, "AES");
        } finally {
            // SecretKeySpec kendi kopyasını tutar, ara diziler burada temizlenebilir.
            Arrays.fill(hash, (byte) 0);
            Arrays.fill(key, (byte) 0);
        }
    }

    private static void validateParameters(ECParameterSpec actual) throws GeneralSecurityException {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(CURVE_NAME));
        ECParameterSpec expected = parameters.getParameterSpec(ECParameterSpec.class);

        // Yalnızca alan boyutuna bakılmaz, eğrinin tüm parametreleri eşleşmelidir.
        if (actual == null
                || !actual.getCurve().equals(expected.getCurve())
                || !actual.getGenerator().equals(expected.getGenerator())
                || !actual.getOrder().equals(expected.getOrder())
                || actual.getCofactor() != expected.getCofactor()) {
            throw new InvalidKeyException("ECDH anahtarı secp256r1 eğrisine ait değil.");
        }
    }

    private static void validatePublicKey(PublicKey publicKey) throws GeneralSecurityException {
        if (!(publicKey instanceof ECPublicKey ecPublicKey)) {
            throw new InvalidKeyException("ECDH için EC açık anahtarı gerekli.");
        }
        ECParameterSpec parameters = ecPublicKey.getParams();
        validateParameters(parameters);
        ECPoint point = ecPublicKey.getW();
        if (point == null || ECPoint.POINT_INFINITY.equals(point)) {
            throw new InvalidKeyException("ECDH açık noktası geçersiz.");
        }

        BigInteger prime = ((ECFieldFp) parameters.getCurve().getField()).getP();
        BigInteger x = point.getAffineX();
        BigInteger y = point.getAffineY();
        if (x.signum() < 0 || x.compareTo(prime) >= 0 || y.signum() < 0 || y.compareTo(prime) >= 0) {
            throw new InvalidKeyException("ECDH açık noktası alan sınırlarının dışında.");
        }

        // Nokta, y² = x³ + ax + b (mod p) eğri denklemini sağlamalıdır.
        BigInteger left = y.multiply(y).mod(prime);
        BigInteger right = x.multiply(x).multiply(x)
                .add(parameters.getCurve().getA().multiply(x))
                .add(parameters.getCurve().getB()).mod(prime);
        if (!left.equals(right)) {
            throw new InvalidKeyException("ECDH açık noktası eğri üzerinde değil.");
        }
    }
}
