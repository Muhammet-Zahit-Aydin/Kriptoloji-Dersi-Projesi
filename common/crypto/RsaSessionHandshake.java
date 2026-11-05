package common.crypto;

import common.Message;
import common.MessageType;
import common.SecureFrameCodec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;

/** Shared RSA key setup used by both desktop clients. */
public final class RsaSessionHandshake {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int AES_KEY_BYTES = 16;

    private RsaSessionHandshake() { }

    public static byte[] connect(ObjectInputStream in, ObjectOutputStream out, String clientId) throws IOException {
        try {
            Message publicKeyMessage = SecureFrameCodec.decode(in.readUTF());
            if (publicKeyMessage.type() != MessageType.RSA_PUB_KEY_EXCHANGE
                    || !(publicKeyMessage.payload() instanceof byte[] encodedKey)) {
                throw new IOException("Sunucu RSA açık anahtarını göndermedi.");
            }

            PublicKey publicKey = RsaCryptoService.getPublicKeyFromBase64(
                    new String(encodedKey, StandardCharsets.UTF_8));
            byte[] sessionKey = new byte[AES_KEY_BYTES];
            RANDOM.nextBytes(sessionKey); // Her bağlantıya yeni, rastgele 128 bit anahtar.
            byte[] protectedKey = RsaCryptoService.encryptAesKey(sessionKey, publicKey);
            Message keyMessage = new Message(MessageType.AES_KEY_EXCHANGE, clientId, "Server", protectedKey, null);
            out.writeUTF(SecureFrameCodec.encode(keyMessage));
            out.flush();

            Message acknowledgement = SecureFrameCodec.decode(in.readUTF());
            if (acknowledgement.type() != MessageType.HANDSHAKE_SUCCESS) {
                throw new IOException(acknowledgement.type() == MessageType.HANDSHAKE_FAILED
                        ? "Sunucu RSA el sıkışmasını reddetti."
                        : "Sunucudan RSA el sıkışma ACK'i alınamadı.");
            }
            return sessionKey;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("RSA el sıkışması başarısız.", e);
        }
    }
}
