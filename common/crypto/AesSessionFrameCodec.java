package common.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/** Protects each client/server frame with that connection's AES session key. */
public final class AesSessionFrameCodec {
    private static final String PREFIX = "\u001eKRIPTO1S:";
    private static final byte[] AAD = PREFIX.getBytes(StandardCharsets.US_ASCII);
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private AesSessionFrameCodec() { }

    public static String encode(String frame, byte[] key) throws IOException {
        if (frame == null) throw new IOException("Boş oturum çerçevesi.");
        requireKey(key);
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            RANDOM.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(AAD);
            byte[] encrypted = cipher.doFinal(frame.getBytes(StandardCharsets.UTF_8));
            byte[] body = new byte[nonce.length + encrypted.length];
            System.arraycopy(nonce, 0, body, 0, nonce.length);
            System.arraycopy(encrypted, 0, body, nonce.length, encrypted.length);
            return PREFIX + Base64.getEncoder().encodeToString(body);
        } catch (GeneralSecurityException e) {
            throw new IOException("Oturum çerçevesi şifrelenemedi.", e);
        }
    }

    public static String decode(String frame, byte[] key) throws IOException {
        if (!isSessionFrame(frame)) throw new IOException("Güvenli oturum çerçevesi bekleniyordu.");
        requireKey(key);
        try {
            byte[] body = Base64.getDecoder().decode(frame.substring(PREFIX.length()));
            if (body.length < NONCE_BYTES + TAG_BITS / 8) throw new IOException("Oturum çerçevesi eksik.");
            byte[] nonce = new byte[NONCE_BYTES];
            byte[] encrypted = new byte[body.length - NONCE_BYTES];
            System.arraycopy(body, 0, nonce, 0, nonce.length);
            System.arraycopy(body, nonce.length, encrypted, 0, encrypted.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(AAD);
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IOException("Oturum çerçevesi doğrulanamadı.", e);
        }
    }

    public static boolean isSessionFrame(String frame) {
        return frame != null && frame.startsWith(PREFIX);
    }

    private static void requireKey(byte[] key) throws IOException {
        if (key == null || key.length != 16) throw new IOException("AES oturum anahtarı 16 byte olmalı.");
    }
}
