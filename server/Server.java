package server;

import common.FileTransfer;
import common.FileTransferReceiver;
import common.Message;
import common.MessageType;
import common.SecureFrameCodec;
import common.crypto.AesSessionFrameCodec;
import common.crypto.RsaCryptoService;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.Set;
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
        RsaCryptoService rsaService = new RsaCryptoService();
        try {
            rsaService.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("RSA KeyPair üretilemedi", e);
        }

        System.out.println("[DİNLENİYOR] Sunucu " + PORT + " portunda başlatıldı...");
        try (ServerSocket listener = new ServerSocket(PORT)) {
            while (true) {
                Socket socket = listener.accept();
                Thread.startVirtualThread(() -> handleClient(socket, rsaService));
            }
        } catch (IOException e) {
            System.err.println("Sunucu başlatılamadı: " + e.getMessage());
        }
    }

    private static void handleClient(Socket socket, RsaCryptoService rsaService) {
        Session session = null;
        try (socket;
             FileTransferReceiver files = new FileTransferReceiver();
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())) {
            out.flush();
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            Session pending = completeHandshake(socket, out, in, rsaService);
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
                                             ObjectInputStream in, RsaCryptoService rsaService) throws IOException {
        try {
            socket.setSoTimeout(5000);
            Message publicKey = new Message(MessageType.RSA_PUB_KEY_EXCHANGE,
                    rsaService.getPublicKeyAsBase64().getBytes(StandardCharsets.UTF_8));
            out.writeUTF(SecureFrameCodec.encode(publicKey));
            out.flush();

            Message request = SecureFrameCodec.decode(in.readUTF());
            if (request.type() != MessageType.AES_KEY_EXCHANGE
                    || !(request.payload() instanceof byte[] encryptedKey)
                    || request.senderId() == null || request.senderId().isBlank()) {
                sendHandshakeResult(out, false);
                return null;
            }

            byte[] key = rsaService.decryptAesKey(encryptedKey);
            if (key.length != 16) {
                sendHandshakeResult(out, false);
                return null;
            }
            sendHandshakeResult(out, true); // ACK gelince istemci güvenli kanala geçebilir.
            return new Session(socket, out, request.senderId(), key);
        } catch (Exception e) {
            try { sendHandshakeResult(out, false); } catch (IOException ignored) { }
            if (e instanceof IOException io) throw io;
            throw new IOException("RSA anahtar değişimi doğrulanamadı.", e);
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

