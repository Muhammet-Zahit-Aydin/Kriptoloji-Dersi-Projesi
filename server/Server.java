package server;

import common.FileTransfer;
import common.FileTransferReceiver;
import common.Message;
import common.MessageType;
import common.SecureFrameCodec;
import common.crypto.AesSessionFrameCodec;
import common.crypto.DiffieHellmanUtils;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.spec.SecretKeySpec;

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
            
            // 1. Sunucu kendi DH anahtar çiftini üretir
            KeyPair serverKeyPair = DiffieHellmanUtils.generateDHKeyPair();
            
            // 2. Sunucunun DH Public Key'ini istemciye gönder
            Message publicKeyMessage = new Message(MessageType.DH_PUB_KEY_EXCHANGE,
                    serverKeyPair.getPublic().getEncoded());
            out.writeUTF(SecureFrameCodec.encode(publicKeyMessage));
            out.flush();

            // 3. İstemciden gelen DH Public Key'i ve İstemci ID'sini bekle
            Message request = SecureFrameCodec.decode(in.readUTF());
            if (request.type() != MessageType.DH_PUB_KEY_EXCHANGE
                    || !(request.payload() instanceof byte[] clientPubKeyBytes)
                    || request.senderId() == null || request.senderId().isBlank()) {
                sendHandshakeResult(out, false);
                return null;
            }

            // 4. İstemcinin Public Key'ini dönüştür, Shared Secret hesapla ve AES anahtarını türet
            PublicKey clientPubKey = DiffieHellmanUtils.getPublicKeyFromBytes(clientPubKeyBytes);
            byte[] sharedSecret = DiffieHellmanUtils.computeSharedSecret(serverKeyPair.getPrivate(), clientPubKey);
            SecretKeySpec aesSessionKey = DiffieHellmanUtils.deriveAes128Key(sharedSecret);
            byte[] keyBytes = aesSessionKey.getEncoded();

            // 5. Başarılı olduğunu istemciye bildir
            sendHandshakeResult(out, true); 
            return new Session(socket, out, request.senderId(), keyBytes);
            
        } catch (Exception e) {
            try { sendHandshakeResult(out, false); } catch (IOException ignored) { }
            if (e instanceof IOException io) throw io;
            throw new IOException("Diffie-Hellman anahtar değişimi doğrulanamadı.", e);
        }
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