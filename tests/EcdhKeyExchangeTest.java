package tests;

import common.crypto.DiffieHellmanUtils;
import common.crypto.EcdhUtils;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

/** Ortak ECDH bileşeni için referans vektör, anahtar doğrulama ve yenileme testleri. */
public final class EcdhKeyExchangeTest {
    private EcdhKeyExchangeTest() { }

    public static void main(String[] args) throws Exception {
        referenceVector();
        invalidKeys();
        freshKeys();
        System.out.println("PASS: ECDH P-256 shared secret matches RFC 5903 section 8.1 in both directions.");
        System.out.println("PASS: SHA-256 derivation matches the expected 128-bit AES key.");
        System.out.println("PASS: ECDH DER/curve/point validation and invalid shared-secret rejection.");
        System.out.println("PASS: Fresh ECDH key pairs produce different AES keys.");
    }

    private static void referenceVector() throws Exception {
        // RFC 5903 bölüm 8.1'de yayımlanan sabit test değerleri kullanılır.
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec curve = parameters.getParameterSpec(ECParameterSpec.class);
        KeyFactory factory = KeyFactory.getInstance("EC");

        PrivateKey clientPrivate = factory.generatePrivate(new ECPrivateKeySpec(hexInteger(
                "C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433"), curve));
        PublicKey clientPublic = factory.generatePublic(new ECPublicKeySpec(new ECPoint(
                hexInteger("DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180"),
                hexInteger("5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3")), curve));
        PrivateKey peerPrivate = factory.generatePrivate(new ECPrivateKeySpec(hexInteger(
                "C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53"), curve));
        PublicKey peerPublic = factory.generatePublic(new ECPublicKeySpec(new ECPoint(
                hexInteger("D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63"),
                hexInteger("56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB")), curve));

        // DER kodlaması değişimden sonra tekrar çözülür, yalnızca nesneler paylaşılmaz.
        PublicKey peerAtClient = EcdhUtils.getPublicKeyFromBytes(peerPublic.getEncoded());
        PublicKey clientAtPeer = EcdhUtils.getPublicKeyFromBytes(clientPublic.getEncoded());
        byte[] clientSecret = EcdhUtils.computeSharedSecret(clientPrivate, peerAtClient);
        byte[] peerSecret = EcdhUtils.computeSharedSecret(peerPrivate, clientAtPeer);
        byte[] expectedSecret = HexFormat.of().parseHex(
                "D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE");
        check(Arrays.equals(clientSecret, expectedSecret), "Client-2 ortak sırrı referansla eşleşmedi");
        check(Arrays.equals(peerSecret, expectedSecret), "Test eşinin ortak sırrı referansla eşleşmedi");
        check(Arrays.equals(clientAtPeer.getEncoded(), clientPublic.getEncoded()), "X.509 DER kodlaması değişti");

        // Referans sırrın SHA-256 özeti bağımsız hesaplanarak bu beklenen değer sabitlenmiştir.
        byte[] expectedAesKey = HexFormat.of().parseHex("0519dc09b36efad1d00aef1d5b53b100");
        check(Arrays.equals(EcdhUtils.deriveAes128Key(clientSecret).getEncoded(), expectedAesKey),
                "Client-2 AES-128 türetmesi beklenen değerle eşleşmedi");
        check(Arrays.equals(EcdhUtils.deriveAes128Key(peerSecret).getEncoded(), expectedAesKey),
                "Test eşinin AES-128 türetmesi beklenen değerle eşleşmedi");
    }

    private static void invalidKeys() throws Exception {
        for (byte[] encoded : new byte[][] {null, new byte[0], new byte[] {1, 2, 3}}) {
            expectFailure(() -> EcdhUtils.getPublicKeyFromBytes(encoded), "Bozuk açık anahtar kabul edildi");
        }

        KeyPair validPair = EcdhUtils.generateKeyPair();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair otherCurve = generator.generateKeyPair();
        expectFailure(() -> EcdhUtils.getPublicKeyFromBytes(otherCurve.getPublic().getEncoded()),
                "Farklı eğriye ait açık anahtar kabul edildi");
        expectFailure(() -> EcdhUtils.computeSharedSecret(otherCurve.getPrivate(), validPair.getPublic()),
                "Farklı eğriye ait özel anahtar kabul edildi");
        expectFailure(() -> EcdhUtils.computeSharedSecret(validPair.getPrivate(), otherCurve.getPublic()),
                "Farklı eğriyle ortak sır hesaplandı");

        PublicKey dhPublic = DiffieHellmanUtils.generateDHKeyPair().getPublic();
        expectFailure(() -> EcdhUtils.getPublicKeyFromBytes(dhPublic.getEncoded()), "EC olmayan DER anahtarı kabul edildi");
        expectFailure(() -> EcdhUtils.computeSharedSecret(validPair.getPrivate(), dhPublic), "DH anahtarı ECDH'de kabul edildi");

        // Geçerli DER zarfı içindeki açık nokta (0,0) yapılarak eğri kontrolü denenir.
        byte[] invalidPoint = validPair.getPublic().getEncoded();
        Arrays.fill(invalidPoint, invalidPoint.length - 64, invalidPoint.length, (byte) 0);
        expectFailure(() -> EcdhUtils.getPublicKeyFromBytes(invalidPoint), "Eğri dışındaki nokta kabul edildi");

        for (byte[] secret : new byte[][] {null, new byte[0], new byte[31], new byte[33]}) {
            expectFailure(() -> EcdhUtils.deriveAes128Key(secret), "Geçersiz ortak sır boyutu kabul edildi");
        }
    }

    private static void freshKeys() throws Exception {
        KeyPair firstClient = EcdhUtils.generateKeyPair();
        KeyPair secondClient = EcdhUtils.generateKeyPair();
        KeyPair peer = EcdhUtils.generateKeyPair();
        byte[] firstSecret = EcdhUtils.computeSharedSecret(firstClient.getPrivate(), peer.getPublic());
        byte[] secondSecret = EcdhUtils.computeSharedSecret(secondClient.getPrivate(), peer.getPublic());
        check(!Arrays.equals(firstClient.getPublic().getEncoded(), secondClient.getPublic().getEncoded()),
                "Yeni anahtar çifti üretilmedi");
        check(!Arrays.equals(EcdhUtils.deriveAes128Key(firstSecret).getEncoded(),
                EcdhUtils.deriveAes128Key(secondSecret).getEncoded()), "Yeni ECDH anahtarları aynı AES anahtarını üretti");
    }

    private static BigInteger hexInteger(String value) {
        return new BigInteger(value, 16);
    }

    @FunctionalInterface
    private interface SecurityAction {
        void run() throws GeneralSecurityException;
    }

    private static void expectFailure(SecurityAction action, String message) throws GeneralSecurityException {
        try {
            action.run();
        } catch (GeneralSecurityException expected) {
            return;
        }
        throw new AssertionError(message);
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
