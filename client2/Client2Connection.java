package client2;

import common.Message;
import common.MessageType;
import common.FileTransfer;
import common.FileTransferReceiver;
import common.FileTransferSender;
import common.InsecureFrameCodec;

import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;

/** Güncel sunucu ve Client-1 ile aynı ObjectStream + readUTF/writeUTF taşıması. */
public final class Client2Connection implements AutoCloseable {
    public static final String CLIENT_ID = "Client2";
    private static final int TIMEOUT_MS = 5000;

    private final Socket socket;
    private final ObjectOutputStream out;
    private final ObjectInputStream in;
    private final Listener listener;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean receiving = new AtomicBoolean();
    private final AtomicBoolean fileSending = new AtomicBoolean();
    private final FileTransferReceiver fileReceiver = new FileTransferReceiver();

    /** Bildirimler ağ iş parçacığından gelebilir; arayüz EDT'ye aktarmalıdır. */
    public interface Listener {
        void onMessage(Message message);
        void onDisconnected(String reason);

        default void onFileProgress(FileTransfer.Start file, long receivedBytes) { }
        default void onFileReceived(FileTransferReceiver.ReceivedFile file) {
            try { file.close(); } catch (IOException ignored) { }
        }
    }

    private Client2Connection(Socket socket, ObjectOutputStream out,
                              ObjectInputStream in, Listener listener) {
        this.socket = socket;
        this.out = out;
        this.in = in;
        this.listener = listener;
    }

    /** Güncel güvensiz sunucu REGISTER/ACK kullanmaz; akış başlıkları beklenir. */
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
            socket.setSoTimeout(0); // Boşta duran sohbet bağlantısı açık kalır.
            return new Client2Connection(socket, out, in, listener);
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
        // Yerel boyut hatası, sağlam bir bağlantıyı kapatmaz.
        writeFrame(InsecureFrameCodec.encode(new Message(MessageType.TEXT, text)));
    }

    public void sendPdf(Path path, BiConsumer<FileTransfer.Start, Long> progress) throws IOException {
        Objects.requireNonNull(progress, "progress");
        if (!fileSending.compareAndSet(false, true)) throw new IOException("Bir PDF zaten gönderiliyor.");
        AtomicBoolean started = new AtomicBoolean();
        try {
            FileTransfer.Start metadata = FileTransferSender.inspect(path);
            FileTransferSender.send(path, metadata, CLIENT_ID, "Client1", message -> {
                started.set(true);
                writeFrame(InsecureFrameCodec.encode(message));
            }, bytes -> progress.accept(metadata, bytes));
        } catch (IOException e) {
            // END gönderilemeyen aktarım alıcıda tamamlanmış sayılmamalı.
            if (started.get()) disconnect("PDF gönderimi yarıda kesildi: " + e.getMessage());
            throw e;
        } finally {
            fileSending.set(false);
        }
    }

    private void writeFrame(String frame) throws IOException {
        try {
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

    private void receiveLoop() {
        try {
            while (!closed.get()) {
                Message message = InsecureFrameCodec.decode(in.readUTF());
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
            closeSocket(socket); // Bekleyen readUTF çağrısını da sonlandırır.
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
        } catch (IOException ignored) {
            // Bağlantı zaten kapatılıyor.
        }
    }

    @Override
    public void close() {
        disconnect("Bağlantı kesildi.");
    }
}
