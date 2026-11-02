package server;

import common.SecureFrameCodec;
import common.crypto.RsaCryptoService;
import common.FileTransfer;
import common.FileTransferReceiver;
import common.Message;
import common.MessageType;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** UTF-frame relay used by both desktop clients. */
public final class Server {
    private static final int PORT = 5000;
    private static final Path FILE_DIRECTORY = Path.of(
            System.getProperty("kriptoloji.server.files", "server-files")).toAbsolutePath().normalize();
    private static final Set<Session> clients = ConcurrentHashMap.newKeySet();

    private static final class Session {
        final Socket socket;
        final ObjectOutputStream out;
        Session(Socket socket, ObjectOutputStream out) { this.socket = socket; this.out = out; }
        void send(String frame) throws IOException {
            synchronized (out) { out.writeUTF(frame); out.flush(); }
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
                // rsaService nesnesini yeni thread'e parametre olarak aktarıyoruz
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
            
            // --- HANDSHAKE BAŞLANGICI ---
            String encodedPubKey = rsaService.getPublicKeyAsBase64();
            Message pubKeyMsg = new Message(MessageType.RSA_PUB_KEY_EXCHANGE, encodedPubKey.getBytes());
            // Projenizdeki stream veya codec yapısına göre mesajı gönderin
            out.writeUTF(SecureFrameCodec.encode(pubKeyMsg)); 
            out.flush();

            // İstemciden AES anahtarını bekle
            String responseFrame = in.readUTF();
            Message response = SecureFrameCodec.validateForRelay(responseFrame);
            
            if (response != null && response.type() == MessageType.AES_KEY_EXCHANGE) {
                try {
                    // payload()'dan dönen Object, byte dizisine cast ediliyor
                    byte[] decryptedAesKey = rsaService.decryptAesKey((byte[]) response.payload());
                    
                    Message successMsg = new Message(MessageType.HANDSHAKE_SUCCESS, new byte[0]);
                    out.writeUTF(SecureFrameCodec.encode(successMsg));
                    out.flush();
                } catch (Exception e) {
                    Message failMsg = new Message(MessageType.HANDSHAKE_FAILED, new byte[0]);
                    out.writeUTF(SecureFrameCodec.encode(failMsg));
                    out.flush();
                    return; 
                }
            } else {
                return; // Beklenmeyen mesaj tipi, thread'i sonlandır
            }
            // --- HANDSHAKE BİTİŞİ ---

            session = new Session(socket, out);
            clients.add(session);
            System.out.println("[BAĞLANDI] " + socket.getRemoteSocketAddress());
            
            // Asıl mesajlaşma döngüsü
            while (true) {
                String frame = in.readUTF();
                // ... (mevcut while döngünüz buraya gelecek)
            }
        } catch (IOException e) {
            System.out.println("[BAĞLANTI KAPANDI] " + socket.getRemoteSocketAddress() + " | " + e.getMessage());
        } finally {
            if (session != null) clients.remove(session);
        }
    }
}