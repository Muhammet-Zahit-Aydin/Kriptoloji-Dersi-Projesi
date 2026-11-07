package client2;

import common.FileTransfer;
import common.FileTransferReceiver;
import common.FileTransferSender;
import common.Message;
import common.MessageType;
import common.SecureFrameCodec;
import common.crypto.AesSessionFrameCodec;
import common.crypto.CryptoMode;
import common.crypto.KeyExchangeMethod;
import common.crypto.SessionHandshake;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UTFDataFormatException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;

/** Client-2 bağlantısını, oturum kurulumunu ve mevcut metin/PDF taşımasını yönetir. */
public final class Client2Connection implements AutoCloseable {
    public static final String CLIENT_ID = "Client2";
    private static final int TIMEOUT_MS = 5000;

    // Bu bağlantının akışları ve anahtarı başka bir oturumla paylaşılmaz.
    private final Socket socket;
    private final ObjectOutputStream out;
    private final ObjectInputStream in;
    private final Listener listener;
    private final CryptoMode cryptoMode;
    private final String password;
    private final byte[] sessionKey;

    // Ağ ve arayüz iş parçacıkları aynı anda kapatma/gönderme isteyebilir.
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean receiving = new AtomicBoolean();
    private final AtomicBoolean fileSending = new AtomicBoolean();
    private final FileTransferReceiver fileReceiver = new FileTransferReceiver();

    /** Bildirimler ağ iş parçacığından gelir; Swing'e aktarımı arayüz sınıfı yapar. */
    public interface Listener {
        void onMessage(Message message);
        void onDisconnected(String reason);

        default void onFileProgress(FileTransfer.Start file, long receivedBytes) { }

        default void onFileReceived(FileTransferReceiver.ReceivedFile file) {
            // Dosyayı kullanmayan dinleyici de geçici kopyayı açık bırakmaz.
            try {
                file.close();
            } catch (IOException ignored) { }
        }
    }

    private Client2Connection(Socket socket, ObjectOutputStream out, ObjectInputStream in,
            Listener listener, CryptoMode mode, String password, byte[] sessionKey) {
        this.socket = socket;
        this.out = out;
        this.in = in;
        this.listener = listener;
        this.cryptoMode = mode;
        this.password = password;
        this.sessionKey = sessionKey.clone();
    }

    /** Varsayılan akış: DH-2048 oturumu, metne ek parola şifrelemesi yok. */
    public static Client2Connection connect(String host, int port, Listener listener) throws IOException {
        return connect(host, port, listener, CryptoMode.INSECURE, null);
    }

    public static Client2Connection connect(String host, int port, Listener listener,
            CryptoMode mode, String password) throws IOException {
        return connect(host, port, listener, mode, password, KeyExchangeMethod.DH_2048);
    }

    /** Başarılı el sıkışma ve ACK tamamlanmadan kullanılabilir bağlantı dönmez. */
    public static Client2Connection connect(String host, int port, Listener listener,
            CryptoMode mode, String password, KeyExchangeMethod method) throws IOException {
        Objects.requireNonNull(listener, "listener");
        Objects.requireNonNull(method, "Anahtar değişim yöntemi gerekli.");
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("Sunucu IP/adresi boş olamaz.");
        }
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Port 1-65535 arasında olmalıdır.");
        }

        CryptoMode selected = mode == null ? CryptoMode.INSECURE : mode;
        if (selected != CryptoMode.INSECURE && (password == null || password.isBlank())) {
            throw new IllegalArgumentException("Şifreli mod için parola gerekli.");
        }

        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(host.trim(), port), TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);

            // İki uç da önce çıkış başlığını gönderir; giriş akışında kilitlenme önlenir.
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            out.flush();
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            byte[] sessionKey = SessionHandshake.connect(in, out, CLIENT_ID, method);

            // Kurulum zaman aşımı normal mesaj bekleyişini kesmemeli.
            socket.setSoTimeout(0);
            return new Client2Connection(socket, out, in, listener, selected, password, sessionKey);
        } catch (IOException | RuntimeException e) {
            closeSocket(socket);
            throw e;
        }
    }

    /** Aynı bağlantı için yalnızca bir alım döngüsü başlatılır. */
    public void startReceiving() {
        if (!closed.get() && receiving.compareAndSet(false, true)) {
            Thread.startVirtualThread(this::receiveLoop);
        }
    }

    public void sendText(String text) throws IOException {
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException("Boş mesaj gönderilemez.");
        }

        String frame;
        try {
            Message message = new Message(MessageType.TEXT, CLIENT_ID, "Client1", text, null);
            String applicationFrame = SecureFrameCodec.encode(message, cryptoMode, password);
            frame = AesSessionFrameCodec.encode(applicationFrame, sessionKey);
        } catch (IllegalArgumentException e) {
            if (e.getCause() instanceof UTFDataFormatException) {
                throw frameLimitError();
            }
            throw new IOException("Metin kodlanamadı: " + e.getMessage(), e);
        }
        writeFrame(frame);
    }

    /** PDF parçalama/ilerleme davranışı ortak göndericide kalır. */
    public void sendPdf(Path path, BiConsumer<FileTransfer.Start, Long> progress) throws IOException {
        Objects.requireNonNull(progress, "progress");
        if (!fileSending.compareAndSet(false, true)) {
            throw new IOException("Bir PDF zaten gönderiliyor.");
        }

        AtomicBoolean started = new AtomicBoolean();
        try {
            FileTransfer.Start metadata = FileTransferSender.inspect(path);
            FileTransferSender.send(path, metadata, CLIENT_ID, "Client1", message -> {
                started.set(true);
                String applicationFrame = SecureFrameCodec.encode(message);
                writeFrame(AesSessionFrameCodec.encode(applicationFrame, sessionKey));
            }, bytes -> progress.accept(metadata, bytes));
        } catch (IOException e) {
            if (started.get()) {
                disconnect("PDF gönderimi yarıda kesildi: " + e.getMessage());
            }
            throw e;
        } finally {
            fileSending.set(false);
        }
    }

    private void writeFrame(String frame) throws IOException {
        // Boyut kontrolü sokete yazmadan yapılır; yerel hata bağlantıyı bozmaz.
        try (DataOutputStream check = new DataOutputStream(new ByteArrayOutputStream())) {
            check.writeUTF(frame);
        } catch (UTFDataFormatException e) {
            throw frameLimitError();
        }

        try {
            // Metin ve PDF aynı çıkış akışını kullandığı için çerçeveler bölünemez.
            synchronized (out) {
                if (closed.get()) {
                    throw new IOException("Sunucu bağlantısı kapalı.");
                }
                out.writeUTF(frame);
                out.flush();
            }
        } catch (IOException e) {
            disconnect("Mesaj gönderilemedi: " + e.getMessage());
            throw e;
        }
    }

    private static UTFDataFormatException frameLimitError() {
        return new UTFDataFormatException("Mesaj 65.535 byte taşıma sınırını aşıyor. Daha kısa bir metin girin.");
    }

    private void receiveLoop() {
        try {
            while (!closed.get()) {
                // Önce bu oturumun AES katmanı, sonra uygulama paketi çözülür.
                String frame = AesSessionFrameCodec.decode(in.readUTF(), sessionKey);
                Message message = SecureFrameCodec.decode(frame, password);
                if (message.type() == MessageType.TEXT) {
                    listener.onMessage(message);
                } else {
                    receiveFile(message);
                }
            }
        } catch (EOFException | SocketException e) {
            disconnect("Sunucu bağlantıyı kapattı.");
        } catch (IOException e) {
            disconnect("Mesaj alınamadı: " + e.getMessage());
        } finally {
            disconnect("Bağlantı kapatıldı.");
        }
    }

    private void receiveFile(Message message) throws IOException {
        synchronized (fileReceiver) {
            switch (message.type()) {
                case FILE_START -> fileReceiver.start((FileTransfer.Start) message.payload());
                case FILE_CHUNK -> fileReceiver.append((FileTransfer.Chunk) message.payload());
                case FILE_END -> {
                    // Yalnızca boyut/sıra/bitiş kontrolünden geçen dosya arayüze verilir.
                    listener.onFileReceived(fileReceiver.finish((FileTransfer.End) message.payload()));
                    return;
                }
                default -> throw new IOException("Beklenmeyen dosya paketi.");
            }
            listener.onFileProgress(fileReceiver.metadata(), fileReceiver.receivedBytes());
        }
    }

    private void disconnect(String reason) {
        if (closed.compareAndSet(false, true)) {
            closeSocket(socket);
            try {
                fileReceiver.close();
            } catch (IOException e) {
                reason += " Geçici PDF temizlenemedi: " + e.getMessage();
            }
            listener.onDisconnected(reason);
        }
    }

    private static void closeSocket(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) { }
    }

    @Override
    public void close() {
        disconnect("Bağlantı kesildi.");
    }
}
