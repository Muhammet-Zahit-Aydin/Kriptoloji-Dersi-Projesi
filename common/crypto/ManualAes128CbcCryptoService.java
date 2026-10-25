package common.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;

/** AES-128-CBC with PKCS#7 padding, implemented with the course AES block cipher. */
public final class ManualAes128CbcCryptoService implements CryptoService {
    private static final int BLOCK = 16;
    private final SecureRandom random = new SecureRandom();

    @Override public byte[] encrypt(byte[] plaintext, byte[] key) throws Exception {
        requireKey(key);
        int padding = BLOCK - (plaintext.length % BLOCK);
        byte[] padded = Arrays.copyOf(plaintext, plaintext.length + padding);
        Arrays.fill(padded, plaintext.length, padded.length, (byte) padding);
        byte[] iv = new byte[BLOCK]; random.nextBytes(iv);
        byte[] output = new byte[BLOCK + padded.length]; System.arraycopy(iv, 0, output, 0, BLOCK);
        byte[] previous = iv.clone();
        for (int offset = 0; offset < padded.length; offset += BLOCK) {
            byte[] block = Arrays.copyOfRange(padded, offset, offset + BLOCK);
            for (int i=0;i<BLOCK;i++) block[i] ^= previous[i];
            previous = ManualAes128.encryptBlock(block, key);
            System.arraycopy(previous, 0, output, BLOCK + offset, BLOCK);
        }
        Arrays.fill(padded, (byte) 0); return output;
    }

    @Override public byte[] decrypt(byte[] ciphertextWithIv, byte[] key) throws Exception {
        requireKey(key);
        if (ciphertextWithIv == null || ciphertextWithIv.length < BLOCK * 2 || ciphertextWithIv.length % BLOCK != 0)
            throw new IllegalArgumentException("AES-CBC verisi IV ve tam bloklar içermeli.");
        byte[] previous = Arrays.copyOf(ciphertextWithIv, BLOCK);
        byte[] plaintext = new byte[ciphertextWithIv.length - BLOCK];
        for (int offset = BLOCK; offset < ciphertextWithIv.length; offset += BLOCK) {
            byte[] encrypted = Arrays.copyOfRange(ciphertextWithIv, offset, offset + BLOCK);
            byte[] block = ManualAes128.decryptBlock(encrypted, key);
            for (int i=0;i<BLOCK;i++) plaintext[offset - BLOCK + i] = (byte)(block[i] ^ previous[i]);
            previous = encrypted;
        }
        int padding = plaintext[plaintext.length - 1] & 255;
        if (padding < 1 || padding > BLOCK) throw new IllegalArgumentException("AES-CBC dolgu doğrulanamadı.");
        int mismatch = 0;
        for (int i = plaintext.length - padding; i < plaintext.length; i++) mismatch |= (plaintext[i] & 255) ^ padding;
        if (mismatch != 0) throw new IllegalArgumentException("AES-CBC dolgu doğrulanamadı.");
        return Arrays.copyOf(plaintext, plaintext.length - padding);
    }

    @Override public byte[] deriveKey(String password, byte[] salt) throws Exception {
        if (password == null || password.isEmpty() || salt == null || salt.length < 16)
            throw new IllegalArgumentException("Parola ve en az 16 byte salt gerekli.");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 120_000, 128);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }

    private static void requireKey(byte[] key) {
        if (key == null || key.length != 16) throw new IllegalArgumentException("AES-128 anahtarı 16 byte olmalı.");
    }
}
