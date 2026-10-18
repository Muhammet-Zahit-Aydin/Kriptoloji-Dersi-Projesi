package client2;

import common.Message;
import common.MessageType;

import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/** Client-2'nin mevcut nesne tabanlı TCP protokolünü kullanan bağlantısı. */
public final class Client2Connection implements AutoCloseable {
    public static final String CLIENT_ID = "Client2";
    private static final int TIMEOUT_MS = 5000;

    private final Socket socket;
    private final ObjectOutputStream out;
    private final ObjectInputStream in;
    private final Listener listener;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean receiving = new AtomicBoolean();

    /** Bildirimler ağ iş parçacığından gelebilir; arayüz EDT'ye aktarmalıdır. */
    public interface Listener {
        void onMessage(Message message);
        void onDisconnected(String reason);
    }

    private Client2Connection(Socket socket, ObjectOutputStream out,
                              ObjectInputStream in, Listener listener) {
        this.socket = socket;
        this.out = out;
        this.in = in;
        this.listener = listener;
    }

    /** TCP bağlantısı ve REGISTER/ACK tamamlanmadan kullanılabilir bağlantı dönmez. */
    public static Client2Connection connect(String host, int port, Listener listener)
            throws IOException {
        Objects.requireNonNull(listener, "listener");
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("Sunucu IP/adresi boş olamaz.");
        }
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Port 1-65535 arasında olmalıdır.");
        }

        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(host.trim(), port), TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);
            // İki taraf da önce çıktı akışını oluşturup başlığı göndermeli.
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            out.flush();
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            out.writeObject(new Message(MessageType.REGISTER, CLIENT_ID));
            out.flush();

            Object response = in.readObject();
            if (!(response instanceof Message message) || message.type() == null) {
                throw new IOException("Sunucu geçerli bir kayıt cevabı göndermedi.");
            }
            if (message.type() == MessageType.ERROR) {
                throw new IOException("Kayıt reddedildi: " + message.payload());
            }
            if (message.type() != MessageType.ACK) {
                throw new IOException("Kayıt için ACK bekleniyordu: " + message.type());
            }

            socket.setSoTimeout(0); // Boşta kalan sohbet bağlantısı zaman aşımına uğramaz.
            return new Client2Connection(socket, out, in, listener);
        } catch (ClassNotFoundException e) {
            closeSocket(socket);
            throw new IOException("Kayıt cevabının mesaj sınıfı tanınmıyor.", e);
        } catch (IOException | RuntimeException e) {
            closeSocket(socket);
            throw e;
        }
    }

    /** Arayüz bağlantıyı sakladıktan sonra sürekli alımı başlatır. */
    public void startReceiving() {
        if (!closed.get() && receiving.compareAndSet(false, true)) {
            Thread.startVirtualThread(this::receiveLoop);
        }
    }

    public void sendText(String text) throws IOException {
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException("Boş mesaj gönderilemez.");
        }
        try {
            synchronized (out) {
                if (closed.get()) {
                    throw new IOException("Sunucu bağlantısı kapalı.");
                }
                out.writeObject(new Message(MessageType.TEXT, text));
                // Uzun oturumlarda nesnelerin çıktı akışında birikmesini önle.
                out.reset();
                out.flush();
            }
        } catch (IOException e) {
            disconnect("Mesaj gönderilemedi: " + e.getMessage());
            throw e;
        }
    }

    private void receiveLoop() {
        try {
            while (!closed.get()) {
                Object value = in.readObject();
                if (!(value instanceof Message message) || message.type() == null) {
                    throw new IOException("Sunucudan geçersiz mesaj alındı.");
                }
                if (message.type() == MessageType.TEXT && !(message.payload() instanceof String)) {
                    throw new IOException("TEXT mesajının içeriği metin olmalıdır.");
                }
                listener.onMessage(message);
            }
        } catch (EOFException | SocketException e) {
            disconnect("Sunucu bağlantıyı kapattı.");
        } catch (IOException | ClassNotFoundException e) {
            disconnect("Mesaj alınamadı: " + e.getMessage());
        } finally {
            disconnect("Bağlantı kapatıldı.");
        }
    }

    private void disconnect(String reason) {
        if (closed.compareAndSet(false, true)) {
            closeSocket(socket); // Bekleyen readObject çağrısını da sonlandırır.
            listener.onDisconnected(reason);
        }
    }

    private static void closeSocket(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
            // Bağlantı zaten kapatılıyor.
        }
    }

    @Override
    public void close() {
        disconnect("Bağlantı kesildi.");
    }
}
