package client2;

import common.FileTransfer;
import common.FileTransferReceiver;
import common.FileTransferSender;
import common.Message;
import common.MessageType;
import common.SecureFrameCodec;
import common.crypto.CryptoMode;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
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

/** Client-2 UTF stream and message/file transport. */
public final class Client2Connection implements AutoCloseable {
    public static final String CLIENT_ID = "Client2";
    private static final int TIMEOUT_MS = 5000;
    private final Socket socket;
    private final ObjectOutputStream out;
    private final ObjectInputStream in;
    private final Listener listener;
    private final CryptoMode cryptoMode;
    private final String password;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean receiving = new AtomicBoolean();
    private final AtomicBoolean fileSending = new AtomicBoolean();
    private final FileTransferReceiver fileReceiver = new FileTransferReceiver();

    public interface Listener {
        void onMessage(Message message);
        void onDisconnected(String reason);
        default void onFileProgress(FileTransfer.Start file, long receivedBytes) { }
        default void onFileReceived(FileTransferReceiver.ReceivedFile file) {
            try { file.close(); } catch (IOException ignored) { }
        }
    }

    private Client2Connection(Socket socket,ObjectOutputStream out,ObjectInputStream in,Listener listener,CryptoMode mode,String password) {
        this.socket=socket; this.out=out; this.in=in; this.listener=listener; this.cryptoMode=mode; this.password=password;
    }

    /** Existing callers keep the insecure compatibility mode. */
    public static Client2Connection connect(String host,int port,Listener listener) throws IOException {
        return connect(host,port,listener,CryptoMode.INSECURE,null);
    }

    public static Client2Connection connect(String host,int port,Listener listener,CryptoMode mode,String password) throws IOException {
        Objects.requireNonNull(listener,"listener");
        if(host==null||host.isBlank()) throw new IllegalArgumentException("Sunucu IP/adresi boş olamaz.");
        if(port<1||port>65535) throw new IllegalArgumentException("Port 1-65535 arasında olmalıdır.");
        CryptoMode selected=mode==null?CryptoMode.INSECURE:mode;
        if(selected!=CryptoMode.INSECURE&&(password==null||password.isBlank())) throw new IllegalArgumentException("Şifreli mod için parola gerekli.");
        Socket socket=new Socket();
        try {
            socket.connect(new InetSocketAddress(host.trim(),port),TIMEOUT_MS); socket.setSoTimeout(TIMEOUT_MS);
            ObjectOutputStream out=new ObjectOutputStream(socket.getOutputStream()); out.flush();
            ObjectInputStream in=new ObjectInputStream(socket.getInputStream()); socket.setSoTimeout(0);
            return new Client2Connection(socket,out,in,listener,selected,password);
        } catch(IOException|RuntimeException e) { closeSocket(socket); throw e; }
    }

    public void startReceiving() { if(!closed.get()&&receiving.compareAndSet(false,true)) Thread.startVirtualThread(this::receiveLoop); }

    public void sendText(String text) throws IOException {
        if(text==null||text.isBlank()) throw new IllegalArgumentException("Boş mesaj gönderilemez.");
        writeFrame(SecureFrameCodec.encode(new Message(MessageType.TEXT,CLIENT_ID,"Client1",text,null),cryptoMode,password));
    }

    public void sendPdf(Path path,BiConsumer<FileTransfer.Start,Long> progress) throws IOException {
        Objects.requireNonNull(progress,"progress");
        if(!fileSending.compareAndSet(false,true)) throw new IOException("Bir PDF zaten gönderiliyor.");
        AtomicBoolean started=new AtomicBoolean();
        try {
            FileTransfer.Start metadata=FileTransferSender.inspect(path);
            FileTransferSender.send(path,metadata,CLIENT_ID,"Client1",message->{ started.set(true); writeFrame(SecureFrameCodec.encode(message)); },bytes->progress.accept(metadata,bytes));
        } catch(IOException e) { if(started.get()) disconnect("PDF gönderimi yarıda kesildi: "+e.getMessage()); throw e; }
        finally { fileSending.set(false); }
    }

    private void writeFrame(String frame) throws IOException {
        try(DataOutputStream check=new DataOutputStream(new ByteArrayOutputStream())) { check.writeUTF(frame); }
        try {
            synchronized(out) { if(closed.get()) throw new IOException("Sunucu bağlantısı kapalı."); out.writeUTF(frame); out.flush(); }
        } catch(IOException e) { disconnect("Mesaj gönderilemedi: "+e.getMessage()); throw e; }
    }

    private void receiveLoop() {
        try { while(!closed.get()) { Message message=SecureFrameCodec.decode(in.readUTF(),password); if(message.type()==MessageType.TEXT) listener.onMessage(message); else receiveFile(message); } }
        catch(EOFException|SocketException e) { disconnect("Sunucu bağlantıyı kapattı."); }
        catch(IOException e) { disconnect("Mesaj alınamadı: "+e.getMessage()); }
        finally { disconnect("Bağlantı kapatıldı."); }
    }

    private void receiveFile(Message message) throws IOException {
        synchronized(fileReceiver) {
            switch(message.type()) {
                case FILE_START -> fileReceiver.start((FileTransfer.Start)message.payload());
                case FILE_CHUNK -> fileReceiver.append((FileTransfer.Chunk)message.payload());
                case FILE_END -> { listener.onFileReceived(fileReceiver.finish((FileTransfer.End)message.payload())); return; }
                default -> throw new IOException("Beklenmeyen dosya paketi.");
            }
            listener.onFileProgress(fileReceiver.metadata(),fileReceiver.receivedBytes());
        }
    }

    private void disconnect(String reason) {
        if(closed.compareAndSet(false,true)) {
            closeSocket(socket);
            try { fileReceiver.close(); } catch(IOException e) { reason += " Geçici PDF temizlenemedi: "+e.getMessage(); }
            listener.onDisconnected(reason);
        }
    }
    private static void closeSocket(Socket socket) { try { socket.close(); } catch(IOException ignored) { } }
    @Override public void close() { disconnect("Bağlantı kesildi."); }
}
