package tests;

import client2.Client2Connection;
import common.*;
import common.FileTransferReceiver.ReceivedFile;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Güncel UTF taşıması ve ortak PDF sözleşmesi için gerçek loopback TCP testleri. */
public final class Client2ConnectionTest {
    private static final String TEXT = "Türkçe: ığüşöç İĞÜŞÖÇ — Merhaba 👋\nİkinci satır\u0000";

    private static final class Events implements Client2Connection.Listener {
        final BlockingQueue<Message> messages = new LinkedBlockingQueue<>();
        final BlockingQueue<String> disconnects = new LinkedBlockingQueue<>();
        final BlockingQueue<ReceivedFile> files = new LinkedBlockingQueue<>();
        final BlockingQueue<Long> progress = new LinkedBlockingQueue<>();
        final AtomicInteger disconnectCount = new AtomicInteger();
        public void onMessage(Message message) { messages.add(message); }
        public void onDisconnected(String reason) {
            disconnectCount.incrementAndGet();
            disconnects.add(reason);
        }
        public void onFileProgress(FileTransfer.Start file, long bytes) { progress.add(bytes); }
        public void onFileReceived(ReceivedFile file) { files.add(file); }
    }

    @FunctionalInterface
    private interface PeerAction { void run(ObjectInputStream in, ObjectOutputStream out) throws Exception; }

    private static final class Peer implements AutoCloseable {
        final ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        final CompletableFuture<Void> finished = new CompletableFuture<>();
        volatile Socket accepted;
        Peer(PeerAction action) throws IOException {
            Thread.startVirtualThread(() -> {
                try (Socket socket = server.accept()) {
                    accepted = socket;
                    socket.setSoTimeout(8000);
                    ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                    out.flush();
                    ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                    action.run(in, out); // Güncel sunucu gibi REGISTER/ACK kullanmaz.
                    finished.complete(null);
                } catch (Throwable e) { finished.completeExceptionally(e); }
            });
        }
        Client2Connection connect(Events events) throws IOException {
            return Client2Connection.connect(server.getInetAddress().getHostAddress(), server.getLocalPort(), events);
        }
        void await() throws Exception { finished.get(10, TimeUnit.SECONDS); }
        public void close() throws IOException {
            server.close();
            if (accepted != null) accepted.close();
        }
    }

    public static void main(String[] args) throws Exception {
        textAndLimits();
        pdfSendReceiveAndSave();
        incompleteAndInvalidPdf();
        fileContractValidation();
        remoteDisconnectAndReconnect();
        invalidAddress();
        System.out.println("PASS: UTF text, Turkish/emoji/NUL, frame limit, disconnect and reconnect.");
        System.out.println("PASS: PDF START/CHUNK/END, progress, save, binary equality and invalid/incomplete transfers.");
    }

    private static void textAndLimits() throws Exception {
        String escaped = "\u001eKRIPTO1:bu bir metindir";
        try (Peer peer = new Peer((in, out) -> {
            for (String expected : new String[] {TEXT, TEXT, "x".repeat(65535), escaped, TEXT}) {
                String frame = in.readUTF();
                check(InsecureFrameCodec.decode(frame).payload().equals(expected), "TEXT değişti");
                if (expected.equals(TEXT)) check(frame.equals(TEXT), "Client-1 uyumluluğu bozuldu");
                out.writeUTF(frame);
                out.flush();
            }
            expectEof(in);
        })) {
            Events events = new Events();
            Client2Connection connection = peer.connect(events);
            try (connection) {
                connection.startReceiving();
                connection.startReceiving();
                try {
                    connection.sendText(" \t\n");
                    throw new AssertionError("Boş mesaj kabul edildi");
                } catch (IllegalArgumentException expected) { }
                for (String text : new String[] {TEXT, TEXT, "x".repeat(65535), escaped}) {
                    connection.sendText(text);
                    check(take(events.messages).payload().equals(text), "Gelen metin değişti");
                }
                try {
                    connection.sendText("ğ".repeat(32768));
                    throw new AssertionError("UTF sınırı aşılabildi");
                } catch (UTFDataFormatException expected) { }
                check(events.disconnects.isEmpty(), "Yerel boyut hatası bağlantıyı kapattı");
                connection.sendText(TEXT);
                check(take(events.messages).payload().equals(TEXT), "Boyut hatasından sonra gönderilemedi");
            }
            connection.close();
            peer.await();
            take(events.disconnects);
            check(events.disconnectCount.get() == 1, "Kopma birden fazla bildirildi");
        }
    }

    private static void pdfSendReceiveAndSave() throws Exception {
        Path directory = Files.createTempDirectory("client2-pdf-test-");
        Path source = directory.resolve("Türkçe belge.pdf");
        byte[] content = pdfBytes();
        Files.write(source, content);
        try (Peer peer = new Peer((in, out) -> {
            try (FileTransferReceiver receiver = new FileTransferReceiver()) {
                Message first = InsecureFrameCodec.decode(in.readUTF());
                check(first.type() == MessageType.FILE_START, "START eksik");
                check("Client2".equals(first.senderId()) && "Client1".equals(first.targetId()), "Kimlik eksik");
                receiver.start((FileTransfer.Start) first.payload());
                int chunks = 0;
                while (true) {
                    Message message = InsecureFrameCodec.decode(in.readUTF());
                    if (message.type() == MessageType.FILE_END) {
                        try (ReceivedFile file = receiver.finish((FileTransfer.End) message.payload())) {
                            Path copy = directory.resolve("sent.pdf");
                            file.saveTo(copy);
                            check(Arrays.equals(content, Files.readAllBytes(copy)), "Gönderilen PDF bozuldu");
                        }
                        break;
                    }
                    receiver.append((FileTransfer.Chunk) message.payload());
                    chunks++;
                }
                check(chunks > 1, "Çok parçalı aktarım denenmedi");
                FileTransferSender.send(source, FileTransferSender.inspect(source), "Client1", "Client2",
                        packet -> { out.writeUTF(InsecureFrameCodec.encode(packet)); out.flush(); }, bytes -> { });
                expectEof(in);
            }
        })) {
            Events events = new Events();
            try (Client2Connection connection = peer.connect(events)) {
                connection.startReceiving();
                long[] sent = {-1};
                connection.sendPdf(source, (file, bytes) -> {
                    check(bytes >= sent[0] && bytes <= content.length, "Gönderim ilerlemesi geçersiz");
                    sent[0] = bytes;
                });
                check(sent[0] == content.length, "Gönderim ilerlemesi tamamlanmadı");
                try (ReceivedFile received = take(events.files)) {
                    check(received.metadata().fileName().equals(source.getFileName().toString()), "PDF adı değişti");
                    check(received.metadata().size() == content.length, "PDF boyutu değişti");
                    Path destination = directory.resolve("received.pdf");
                    received.saveTo(destination);
                    check(Arrays.equals(content, Files.readAllBytes(destination)), "Alınan PDF bozuldu");
                    try {
                        received.saveTo(destination);
                        throw new AssertionError("Mevcut dosya ezildi");
                    } catch (FileAlreadyExistsException expected) { }
                    Path retry = directory.resolve("retry.pdf");
                    received.saveTo(retry);
                    check(Arrays.equals(content, Files.readAllBytes(retry)), "Kaydetme tekrar denenemedi");
                }
                long previous = -1;
                for (long bytes : events.progress) {
                    check(bytes >= previous && bytes <= content.length, "Alım ilerlemesi geçersiz");
                    previous = bytes;
                }
                check(previous == content.length, "Alım ilerlemesi eksik");
            }
            peer.await();
        } finally {
            for (String name : new String[] {"Türkçe belge.pdf", "sent.pdf", "received.pdf", "retry.pdf"}) {
                Files.deleteIfExists(directory.resolve(name));
            }
            Files.deleteIfExists(directory);
        }
    }

    private static void incompleteAndInvalidPdf() throws Exception {
        byte[] content = pdfBytes();
        for (int scenario = 0; scenario < 3; scenario++) {
            final int mode = scenario;
            try (Peer peer = new Peer((in, out) -> {
                UUID id = UUID.randomUUID();
                send(out, MessageType.FILE_START, new FileTransfer.Start(id, "incomplete.pdf", content.length));
                send(out, MessageType.FILE_CHUNK, new FileTransfer.Chunk(id, mode == 2 ? 1 : 0,
                        Arrays.copyOf(content, FileTransfer.CHUNK_SIZE)));
                if (mode == 1) send(out, MessageType.FILE_END, new FileTransfer.End(id, 1));
                if (mode != 0) expectEof(in);
            })) {
                Events events = new Events();
                try (Client2Connection connection = peer.connect(events)) {
                    connection.startReceiving();
                    take(events.disconnects);
                    check(events.files.isEmpty(), "Eksik veya hatalı PDF tamamlanmış sayıldı");
                    peer.await();
                }
            }
        }
    }

    private static void fileContractValidation() throws Exception {
        UUID id = UUID.randomUUID();
        for (String name : new String[] {"../bad.pdf", "C:\\bad.pdf", "bad.txt", "bad\n.pdf"}) {
            try {
                new FileTransfer.Start(id, name, 100);
                throw new AssertionError("Geçersiz PDF adı kabul edildi");
            } catch (IllegalArgumentException expected) { }
        }
        try (FileTransferReceiver receiver = new FileTransferReceiver()) {
            receiver.start(new FileTransfer.Start(id, "test.pdf", 10));
            receiver.append(new FileTransfer.Chunk(id, 0, "%PDF-12345".getBytes(StandardCharsets.US_ASCII)));
            try {
                receiver.append(new FileTransfer.Chunk(id, 0, new byte[] {1}));
                throw new AssertionError("Yinelenen parça kabul edildi");
            } catch (IOException expected) { }
            try {
                receiver.append(new FileTransfer.Chunk(id, 1, new byte[] {1}));
                throw new AssertionError("Bildirilen boyut aşılabildi");
            } catch (IOException expected) { }
            try {
                receiver.finish(new FileTransfer.End(UUID.randomUUID(), 1));
                throw new AssertionError("Yanlış dosya kimliği kabul edildi");
            } catch (IOException expected) { }
            try (ReceivedFile ignored = receiver.finish(new FileTransfer.End(id, 1))) { }
        }
        try {
            InsecureFrameCodec.decode("\u001eKRIPTO1:bad-base64!");
            throw new AssertionError("Bozuk çerçeve kabul edildi");
        } catch (IOException expected) { }
    }

    private static void remoteDisconnectAndReconnect() throws Exception {
        for (int attempt = 0; attempt < 2; attempt++) {
            try (Peer peer = new Peer((in, out) -> check(in.readUTF().equals(TEXT), "Yeniden gönderim başarısız"))) {
                Events events = new Events();
                try (Client2Connection connection = peer.connect(events)) {
                    connection.startReceiving();
                    connection.sendText(TEXT);
                    check(take(events.disconnects).contains("kapattı"), "Sunucu kopması algılanmadı");
                    peer.await();
                }
                check(events.disconnectCount.get() == 1, "Kopma birden fazla bildirildi");
            }
        }
    }

    private static void invalidAddress() throws Exception {
        for (int port : new int[] {0, -1, 65536}) {
            try (Client2Connection ignored = Client2Connection.connect("127.0.0.1", port, new Events())) {
                throw new AssertionError("Geçersiz port kabul edildi");
            } catch (IllegalArgumentException expected) { }
        }
        try (Client2Connection ignored = Client2Connection.connect(" ", 5000, new Events())) {
            throw new AssertionError("Boş sunucu adresi kabul edildi");
        } catch (IllegalArgumentException expected) { }
    }

    private static byte[] pdfBytes() {
        byte[] content = new byte[FileTransfer.CHUNK_SIZE * 2 + 37];
        new Random(445876).nextBytes(content);
        byte[] header = "%PDF-1.7\n".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(header, 0, content, 0, header.length);
        return content; // İkili aktarım fixture'ı; PDF ayrıştırıcısı testi değildir.
    }
    private static void send(ObjectOutputStream out, MessageType type, Object payload) throws IOException {
        out.writeUTF(InsecureFrameCodec.encode(new Message(type, "Client1", "Client2", payload, null)));
        out.flush();
    }
    private static void expectEof(ObjectInputStream in) throws Exception {
        try { in.readUTF(); throw new AssertionError("İstemci soketi kapatmadı"); }
        catch (EOFException expected) { }
    }
    private static <T> T take(BlockingQueue<T> queue) throws InterruptedException {
        T value = queue.poll(8, TimeUnit.SECONDS);
        check(value != null, "Beklenen ağ olayı zamanında gelmedi");
        return value;
    }
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
