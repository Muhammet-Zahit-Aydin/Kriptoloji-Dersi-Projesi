package server;

import common.FileTransfer;
import common.FileTransferReceiver;
import common.Message;
import common.MessageType;
import common.SecureFrameCodec;
import common.crypto.AesSessionFrameCodec;
import common.crypto.DiffieHellmanUtils;
import common.crypto.KeyExchangeMethod;
import common.crypto.RsaCryptoService;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Set;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;

/** AES-GCM session relay shared by the two desktop clients. */
public final class Server {
    private static final int PORT = 5000;
    private static final Path FILE_DIRECTORY = Path.of(
            System.getProperty("kriptoloji.server.files", "server-files")).toAbsolutePath().normalize();
    private static final Set<Session> clients = ConcurrentHashMap.newKeySet();

    private static final class Session {
        final Socket socket;
        final ObjectOutputStream out;
        final String clientId;
        final byte[] key;

        Session(Socket socket, ObjectOutputStream out, String clientId, byte[] key) {
            this.socket = socket;
            this.out = out;
            this.clientId = clientId;
            this.key = key.clone();
        }

        void send(String applicationFrame) throws IOException {
            String secureFrame = AesSessionFrameCodec.encode(applicationFrame, key);
            synchronized (out) {
                out.writeUTF(secureFrame);
                out.flush();
            }
        }
    }

    public static void main(String[] args) {
        System.out.println("[DİNLENİYOR] Sunucu " + PORT + " portunda başlatıldı...");
        try (ServerSocket listener = new ServerSocket(PORT)) {
            while (true) {
                Socket socket = listener.accept();
                Thread.startVirtualThread(() -> handleClient(socket));
            }
        } catch (IOException e) {
            System.err.println("Sunucu başlatılamadı: " + e.getMessage());
        }
    }

    private static void handleClient(Socket socket) {
        Session session = null;
        try (socket;
             FileTransferReceiver files = new FileTransferReceiver();
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())) {
            out.flush();
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            Session pending = completeHandshake(socket, out, in);
            if (pending == null) return;
            socket.setSoTimeout(0);
            clients.add(pending); // Oturum yalnızca ACK gönderildikten sonra görünür olur.
            session = pending;
            System.out.println("[BAĞLANDI] " + session.clientId + " " + socket.getRemoteSocketAddress());

            while (true) {
                String secureFrame = in.readUTF();
                String applicationFrame = AesSessionFrameCodec.decode(secureFrame, session.key);
                Message message = SecureFrameCodec.validateForRelay(applicationFrame);
                if (message != null) validateFilePacket(message, files);
                relay(applicationFrame, message, session);
            }
        } catch (IOException | RuntimeException e) {
            System.out.println("[BAĞLANTI KAPANDI] " + socket.getRemoteSocketAddress() + " | " + e.getMessage());
        } finally {
            if (session != null) clients.remove(session);
        }
    }

    private static Session completeHandshake(Socket socket, ObjectOutputStream out,
                                             ObjectInputStream in) throws IOException {
        try {
            socket.setSoTimeout(5000);
            Message selection = SecureFrameCodec.decode(in.readUTF());
            if (selection.type() != MessageType.KEY_EXCHANGE_INIT
                    || !(selection.payload() instanceof byte[] methodBytes)
                    || selection.senderId() == null || selection.senderId().isBlank()) {
                throw new IOException("Anahtar değişim yöntemi ve istemci kimliği gerekli.");
            }
            KeyExchangeMethod method = KeyExchangeMethod.valueOf(new String(methodBytes, StandardCharsets.US_ASCII));
            byte[] key = method == KeyExchangeMethod.DH_2048
                    ? acceptDh(in, out, selection.senderId())
                    : acceptRsa(in, out, selection.senderId());

            sendHandshakeResult(out, true);
            System.out.println("[OTURUM] " + selection.senderId() + " | " + method);
            return new Session(socket, out, selection.senderId(), key);
        } catch (Exception e) {
            try { sendHandshakeResult(out, false); } catch (IOException ignored) { }
            if (e instanceof IOException io) throw io;
            throw new IOException("Anahtar değişimi doğrulanamadı.", e);
        }
    }

    /** DH'de iki taraf aynı sırrı hesaplar; AES anahtarı ağdan gönderilmez. */
    private static byte[] acceptDh(ObjectInputStream in, ObjectOutputStream out, String clientId) throws Exception {
        KeyPair serverKeys = DiffieHellmanUtils.generateDHKeyPair();
        out.writeUTF(SecureFrameCodec.encode(new Message(MessageType.DH_PUB_KEY_EXCHANGE,
                serverKeys.getPublic().getEncoded())));
        out.flush();

        byte[] encodedKey = readClientKey(in, MessageType.DH_PUB_KEY_EXCHANGE, clientId);
        PublicKey clientKey = DiffieHellmanUtils.getPublicKeyFromBytes(encodedKey);
        byte[] secret = DiffieHellmanUtils.computeSharedSecret(serverKeys.getPrivate(), clientKey);
        try {
            return DiffieHellmanUtils.deriveAes128Key(secret).getEncoded();
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    /** Önceki RSA-2048 akışı yöntem seçiminin arkasında korunur. */
    private static byte[] acceptRsa(ObjectInputStream in, ObjectOutputStream out, String clientId) throws Exception {
        RsaCryptoService rsa = new RsaCryptoService();
        rsa.generateKeyPair();
        out.writeUTF(SecureFrameCodec.encode(new Message(MessageType.RSA_PUB_KEY_EXCHANGE,
                rsa.getPublicKeyAsBase64().getBytes(StandardCharsets.UTF_8))));
        out.flush();

        byte[] encryptedKey = readClientKey(in, MessageType.AES_KEY_EXCHANGE, clientId);
        byte[] key = rsa.decryptAesKey(encryptedKey);
        if (key.length != 16) {
            throw new IOException("AES oturum anahtarı 128 bit olmalı.");
        }
        return key;
    }

    private static byte[] readClientKey(ObjectInputStream in, MessageType type, String clientId) throws IOException {
        Message request = SecureFrameCodec.decode(in.readUTF());
        if (request.type() != type || !(request.payload() instanceof byte[] key)
                || !clientId.equals(request.senderId())) {
            throw new IOException("Beklenen istemci anahtar paketi alınamadı.");
        }
        return key;
    }

    private static void sendHandshakeResult(ObjectOutputStream out, boolean accepted) throws IOException {
        Message result = new Message(accepted ? MessageType.HANDSHAKE_SUCCESS : MessageType.HANDSHAKE_FAILED,
                new byte[0]);
        out.writeUTF(SecureFrameCodec.encode(result));
        out.flush();
    }

    private static void validateFilePacket(Message message, FileTransferReceiver files) throws IOException {
        switch (message.type()) {
            case FILE_START -> files.start((FileTransfer.Start) message.payload());
            case FILE_CHUNK -> files.append((FileTransfer.Chunk) message.payload());
            case FILE_END -> {
                try (FileTransferReceiver.ReceivedFile received = files.finish((FileTransfer.End) message.payload())) {
                    Files.createDirectories(FILE_DIRECTORY);
                    Path destination = FILE_DIRECTORY.resolve(received.metadata().fileId() + ".pdf");
                    received.saveTo(destination);
                    System.out.println("[PDF TAMAMLANDI] " + received.metadata().fileName() + " | "
                            + received.metadata().size() + " byte | " + destination);
                }
            }
            default -> { }
        }
    }

    private static void relay(String applicationFrame, Message message, Session sender) throws IOException {
        for (Session recipient : clients) {
            if (recipient == sender) continue;
            if (message != null && message.targetId() != null && !message.targetId().equals(recipient.clientId)) continue;
            recipient.send(applicationFrame);
        }
    }
}
