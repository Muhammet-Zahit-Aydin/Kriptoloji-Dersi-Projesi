package tests;

import common.crypto.ManualAes128;
import common.crypto.ManualAes128CbcCryptoService;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;

/** AES-128 FIPS 197 blok vektörü ve elle CBC kipinin gidiş-dönüş testi. */
public final class ManualAes128Test {
    private static final HexFormat HEX = HexFormat.of();

    public static void main(String[] args) throws Exception {
        byte[] key = HEX.parseHex("000102030405060708090a0b0c0d0e0f");
        byte[] plaintext = HEX.parseHex("00112233445566778899aabbccddeeff");
        byte[] expected = HEX.parseHex("69c4e0d86a7b0430d8cdb78070b4c55a");
        byte[] encrypted = ManualAes128.encryptBlock(plaintext, key);
        check(Arrays.equals(expected, encrypted), "FIPS 197 AES-128 şifreleme vektörü eşleşmedi");
        check(Arrays.equals(plaintext, ManualAes128.decryptBlock(expected, key)),
                "FIPS 197 AES-128 çözme vektörü eşleşmedi");

        ManualAes128CbcCryptoService cbc = new ManualAes128CbcCryptoService();
        Random random = new Random(445866);
        for (int length : new int[] {0, 1, 15, 16, 17, 1024}) {
            byte[] message = new byte[length];
            random.nextBytes(message);
            byte[] ciphertext = cbc.encrypt(message, key);
            check(Arrays.equals(message, cbc.decrypt(ciphertext, key)),
                    "AES-CBC gidiş-dönüş başarısız; uzunluk=" + length);
        }
        System.out.println("PASS: AES-128 FIPS 197 block encrypt/decrypt vector.");
        System.out.println("PASS: Manual AES-128-CBC round trips including empty and block-boundary inputs.");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
