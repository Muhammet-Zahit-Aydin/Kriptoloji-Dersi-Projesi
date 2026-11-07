package common.crypto;

import common.Message;
import common.MessageType;
import common.SecureFrameCodec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Objects;

/** İki istemci aynı yöntem seçimi ve ACK sırasını kullanarak oturum açar. */
public final class SessionHandshake {
    private SessionHandshake() { }

    /** ACK alınmadan anahtar dönmez; çağıran henüz veri gönderimine açılmaz. */
    public static byte[] connect(ObjectInputStream in, ObjectOutputStream out,
            String clientId, KeyExchangeMethod method) throws IOException {
        Objects.requireNonNull(method, "Anahtar değişim yöntemi gerekli.");
        Message selection = new Message(MessageType.KEY_EXCHANGE_INIT, clientId, "Server",
                method.name().getBytes(StandardCharsets.US_ASCII), null);
        out.writeUTF(SecureFrameCodec.encode(selection));
        out.flush();

        if (method == KeyExchangeMethod.RSA_2048) {
            return RsaSessionHandshake.connect(in, out, clientId);
        }
        return connectDh(in, out, clientId);
    }

    private static byte[] connectDh(ObjectInputStream in, ObjectOutputStream out,
            String clientId) throws IOException {
        byte[] sharedSecret = null;
        try {
            Message response = SecureFrameCodec.decode(in.readUTF());
            if (response.type() != MessageType.DH_PUB_KEY_EXCHANGE
                    || !(response.payload() instanceof byte[] encodedPublicKey)) {
                throw new IOException("Sunucu DH açık anahtarını göndermedi.");
            }

            // Karşı tarafın grubu ve açık değeri doğrulanmadan ortak sır hesaplanmaz.
            PublicKey serverPublicKey = DiffieHellmanUtils.getPublicKeyFromBytes(encodedPublicKey);
            KeyPair clientKeys = DiffieHellmanUtils.generateDHKeyPair();
            sharedSecret = DiffieHellmanUtils.computeSharedSecret(clientKeys.getPrivate(), serverPublicKey);
            byte[] sessionKey = DiffieHellmanUtils.deriveAes128Key(sharedSecret).getEncoded();

            // Ağdan yalnızca açık anahtar gider; ortak sır ve AES anahtarı yerelde kalır.
            Message publicKey = new Message(MessageType.DH_PUB_KEY_EXCHANGE, clientId, "Server",
                    clientKeys.getPublic().getEncoded(), null);
            out.writeUTF(SecureFrameCodec.encode(publicKey));
            out.flush();

            Message acknowledgement = SecureFrameCodec.decode(in.readUTF());
            if (acknowledgement.type() != MessageType.HANDSHAKE_SUCCESS) {
                throw new IOException("Sunucu DH el sıkışmasını onaylamadı.");
            }
            return sessionKey;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("DH el sıkışması başarısız.", e);
        } finally {
            if (sharedSecret != null) {
                Arrays.fill(sharedSecret, (byte) 0);
            }
        }
    }
}
