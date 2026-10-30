package server;

import common.SecureFrameCodec;
import common.FileTransfer;
import common.FileTransferReceiver;
import common.Message;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
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
            session = new Session(socket, out);
            clients.add(session);
            System.out.println("[BAĞLANDI] " + socket.getRemoteSocketAddress());
            while (true) {
                String frame = in.readUTF();
                Message message = SecureFrameCodec.validateForRelay(frame);
                if (message != null) {
                    switch (message.type()) {
                        case TEXT -> System.out.println("[METİN] " + message.payload());
                        case FILE_START -> files.start((FileTransfer.Start) message.payload());
                        case FILE_CHUNK -> files.append((FileTransfer.Chunk) message.payload());
                        case FILE_END -> {
                            try (var completed = files.finish((FileTransfer.End) message.payload())) {
                                Files.createDirectories(FILE_DIRECTORY);
                                Path copy = FILE_DIRECTORY.resolve(completed.metadata().fileId() + ".pdf");
                                completed.saveTo(copy);
                                System.out.println("[PDF KAYDEDİLDİ] " + completed.metadata().fileName()
                                        + " | " + completed.metadata().size() + " byte | " + copy);
                            }
                        }
                        default -> throw new IOException("Desteklenmeyen paket: " + message.type());
                    }
                }
                for (Session recipient : clients) {
                    if (recipient != session) {
                        try { recipient.send(frame); }
                        catch (IOException e) { clients.remove(recipient); try { recipient.socket.close(); } catch (IOException ignored) { } }
                    }
                }
            }
        } catch (IOException e) {
            System.out.println("[BAĞLANTI KAPANDI] " + socket.getRemoteSocketAddress() + " | " + e.getMessage());
        } finally {
            if (session != null) clients.remove(session);
        }
    }
}
