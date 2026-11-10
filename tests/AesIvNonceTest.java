package tests;

import common.Message;
import common.MessageType;
import common.SecureFrameCodec;
import common.crypto.AesSessionFrameCodec;
import common.crypto.CryptoMode;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/** AES kiplerinin IV/nonce boyunu, her mesajda yenilenmesini ve çözmeyi doğrular. */
public final class AesIvNonceTest {
    private static final String PASSWORD = "iv-nonce-test-parolasi";
    private static final String TEXT = "Tekrarlı Türkçe içerik: ığüşöç 👋";
    private static final String APP_PREFIX = "\u001eKRIPTO1:";
    private static final String SESSION_PREFIX = "\u001eKRIPTO1S:";

    public static void main(String[] args) throws Exception {
        verifyProtectedTextModes();
        verifySessionFrames();
        System.out.println("PASS: AES-GCM 96-bit nonces and AES-CBC 128-bit IVs are fresh and decode correctly.");
        System.out.println("PASS: Every AES-GCM session frame carries a fresh 96-bit nonce.");
    }

    private static void verifyProtectedTextModes() throws Exception {
        String gcm1 = SecureFrameCodec.encode(new Message(MessageType.TEXT, "Client1", "Client2", TEXT, null),
                CryptoMode.AES_128_GCM, PASSWORD);
        String gcm2 = SecureFrameCodec.encode(new Message(MessageType.TEXT, "Client1", "Client2", TEXT, null),
                CryptoMode.AES_128_GCM, PASSWORD);
        byte[] gcmPayload1 = encryptedPayload(gcm1, 5, 0);
        byte[] gcmPayload2 = encryptedPayload(gcm2, 5, 0);
        check(gcmPayload1.length == TEXT.getBytes(StandardCharsets.UTF_8).length + 12 + 16,
                "GCM paketi 12 byte nonce ve 16 byte tag içermiyor");
        check(!Arrays.equals(Arrays.copyOf(gcmPayload1, 12), Arrays.copyOf(gcmPayload2, 12)),
                "Aynı GCM anahtarı/parolası altında nonce yenilenmedi");
        check(TEXT.equals(SecureFrameCodec.decode(gcm1, PASSWORD).payload()), "GCM metni çözülemedi");

        String cbc1 = SecureFrameCodec.encode(new Message(MessageType.TEXT, "Client1", "Client2", TEXT, null),
                CryptoMode.AES_128_CBC_MANUAL, PASSWORD);
        String cbc2 = SecureFrameCodec.encode(new Message(MessageType.TEXT, "Client1", "Client2", TEXT, null),
                CryptoMode.AES_128_CBC_MANUAL, PASSWORD);
        byte[] cbcPayload1 = encryptedPayload(cbc1, 6, 32);
        byte[] cbcPayload2 = encryptedPayload(cbc2, 6, 32);
        check(cbcPayload1.length >= 32 && cbcPayload1.length % 16 == 0,
                "CBC paketi 16 byte IV ve tam blok dolgusu içermiyor");
        check(!Arrays.equals(Arrays.copyOf(cbcPayload1, 16), Arrays.copyOf(cbcPayload2, 16)),
                "Aynı CBC anahtarı/parolası altında IV yenilenmedi");
        check(TEXT.equals(SecureFrameCodec.decode(cbc1, PASSWORD).payload()), "CBC metni çözülemedi");
    }

    private static void verifySessionFrames() throws Exception {
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
        String first = AesSessionFrameCodec.encode("same application frame", key);
        String second = AesSessionFrameCodec.encode("same application frame", key);
        check(first.startsWith(SESSION_PREFIX) && second.startsWith(SESSION_PREFIX),
                "Oturum AES-GCM zarfı eksik");
        byte[] firstBody = sessionBody(first);
        byte[] secondBody = sessionBody(second);
        check(firstBody.length >= 12 + 16, "Oturum çerçevesi nonce/tag içermiyor");
        check(!Arrays.equals(Arrays.copyOf(firstBody, 12), Arrays.copyOf(secondBody, 12)),
                "Aynı oturum anahtarı altında GCM nonce yenilenmedi");
        check("same application frame".equals(AesSessionFrameCodec.decode(first, key)),
                "Oturum GCM çerçevesi çözülemedi");
    }

    private static byte[] encryptedPayload(String frame, int expectedKind, int trailerBytes) throws IOException {
        if (frame == null || !frame.startsWith(APP_PREFIX)) throw new IOException("AES uygulama zarfı eksik.");
        byte[] body = Base64.getDecoder().decode(frame.substring(APP_PREFIX.length()));
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(body))) {
            check(in.readUnsignedByte() == expectedKind, "Yanlış AES kip türü.");
            in.readUTF(); // gönderen
            in.readUTF(); // alıcı
            check(in.readNBytes(16).length == 16, "PBKDF2 saltı eksik.");
            int length = in.readInt();
            if (length < 1 || length > in.available() - trailerBytes) throw new IOException("Şifreli içerik boyu geçersiz.");
            byte[] encrypted = in.readNBytes(length);
            check(in.readNBytes(trailerBytes).length == trailerBytes && in.available() == 0,
                    "AES paketi eksik veya fazla veri içeriyor.");
            return encrypted;
        }
    }

    private static byte[] sessionBody(String frame) {
        return Base64.getDecoder().decode(frame.substring(SESSION_PREFIX.length()));
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
