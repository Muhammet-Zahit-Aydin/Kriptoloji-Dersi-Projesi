package tests;

import client2.Client2Connection;
import common.Message;
import common.MessageType;

import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Harici bağımlılık gerektirmeyen, gerçek loopback TCP bağlantılı protokol testleri. */
public final class Client2ConnectionTest {
    private static final String TEXT = "Türkçe: ığüşöç İĞÜŞÖÇ — Merhaba 👋\nİkinci satır";

    private static final class Events implements Client2Connection.Listener {
        final BlockingQueue<Message> messages = new LinkedBlockingQueue<>();
        final BlockingQueue<String> disconnects = new LinkedBlockingQueue<>();
        final AtomicInteger disconnectCount = new AtomicInteger();

        public void onMessage(Message message) { messages.add(message); }
        public void onDisconnected(String reason) {
            disconnectCount.incrementAndGet();
            disconnects.add(reason);
        }
    }

    @FunctionalInterface
    private interface PeerAction {
        void run(ObjectInputStream in, ObjectOutputStream out) throws Exception;
    }

    private static final class Peer implements AutoCloseable {
        final ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        final CompletableFuture<Void> finished = new CompletableFuture<>();
        volatile Socket accepted;

        Peer(PeerAction action) throws IOException {
            Thread.startVirtualThread(() -> {
                try (Socket socket = server.accept()) {
                    accepted = socket;
                    socket.setSoTimeout(5000);
                    ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                    out.flush();
                    ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                    check(in.readObject().equals(new Message(MessageType.REGISTER, "Client2")),
                            "Client2 REGISTER paketi bekleniyordu");
                    action.run(in, out);
                    finished.complete(null);
                } catch (Throwable e) {
                    finished.completeExceptionally(e);
                }
            });
        }

        Client2Connection connect(Events events) throws IOException {
            return Client2Connection.connect(server.getInetAddress().getHostAddress(),
                    server.getLocalPort(), events);
        }

        void await() throws Exception { finished.get(8, TimeUnit.SECONDS); }

        public void close() throws IOException {
            server.close();
            if (accepted != null) accepted.close();
        }
    }

    public static void main(String[] args) throws Exception {
        textAndNotifications();
        registrationFailure(new Message(MessageType.ERROR, "Kimlik kullanımda"), "Kayıt reddedildi");
        registrationFailure(new Message(MessageType.TEXT, "Erken mesaj"), "ACK bekleniyordu");
        registrationFailure("Yanlış paket", "geçerli bir kayıt cevabı");
        invalidIncoming("Yanlış paket");
        invalidIncoming(new Message(MessageType.TEXT, 42));
        remoteDisconnectAndReconnect();
        invalidAddress();
        System.out.println("PASS: Client2 kayıt, çift yönlü Türkçe metin, ACK/ERROR, boş mesaj,");
        System.out.println("      hatalı paket, kopma, yeniden bağlantı ve adres doğrulaması.");
    }

    private static void textAndNotifications() throws Exception {
        try (Peer peer = new Peer((in, out) -> {
            reply(out, new Message(MessageType.ACK, "Kayıt başarılı"));
            // Aynı metni tekrar göndermek de bağımsız bir mesaj olmalı.
            for (int i = 0; i < 2; i++) {
                check(in.readObject().equals(new Message(MessageType.TEXT, TEXT)), "TEXT içeriği değişti");
                reply(out, new Message(MessageType.TEXT, TEXT));
            }
            reply(out, new Message(MessageType.ACK, "Test bildirimi"));
            reply(out, new Message(MessageType.ERROR, "Hedef henüz bağlı değil"));
            expectEof(in);
        })) {
            Events events = new Events();
            Client2Connection connection = peer.connect(events);
            try (connection) {
                connection.startReceiving();
                connection.startReceiving(); // İkinci bir okuyucu oluşturmamalı.
                try {
                    connection.sendText(" \t\n");
                    throw new AssertionError("Boş mesaj kabul edildi");
                } catch (IllegalArgumentException expected) {
                    // Beklenen doğrulama.
                }
                for (int i = 0; i < 2; i++) {
                    connection.sendText(TEXT);
                    check(take(events.messages).equals(new Message(MessageType.TEXT, TEXT)),
                            "Türkçe gelen metin değişti");
                }
                check(take(events.messages).type() == MessageType.ACK, "ACK dinleyiciye ulaşmadı");
                check(take(events.messages).type() == MessageType.ERROR, "ERROR dinleyiciye ulaşmadı");
            }
            connection.close();
            take(events.disconnects);
            peer.await();
            check(events.disconnectCount.get() == 1, "Kopma birden fazla bildirildi");
            try {
                connection.sendText(TEXT);
                throw new AssertionError("Kapalı bağlantı yazmayı kabul etti");
            } catch (IOException expected) {
                // Kapalı bağlantıya gönderim yapılamaz.
            }
        }
    }

    private static void registrationFailure(Object response, String reason) throws Exception {
        try (Peer peer = new Peer((in, out) -> {
            reply(out, response);
            expectEof(in);
        })) {
            Events events = new Events();
            try (Client2Connection ignored = peer.connect(events)) {
                throw new AssertionError("Geçersiz kayıt cevabı kabul edildi");
            } catch (IOException expected) {
                check(expected.getMessage().contains(reason), "Kayıt hata açıklaması yanlış");
            }
            peer.await();
            check(events.messages.isEmpty(), "Kayıt öncesinde mesaj yayımlandı");
        }
    }

    private static void invalidIncoming(Object value) throws Exception {
        try (Peer peer = new Peer((in, out) -> {
            reply(out, new Message(MessageType.ACK, "Kayıt başarılı"));
            reply(out, value);
            expectEof(in);
        })) {
            Events events = new Events();
            try (Client2Connection connection = peer.connect(events)) {
                connection.startReceiving();
                check(take(events.disconnects).contains("Mesaj alınamadı"), "Bozuk paket bildirilmedi");
                check(events.messages.isEmpty(), "Bozuk paket metin olarak gösterildi");
                peer.await();
            }
        }
    }

    private static void remoteDisconnectAndReconnect() throws Exception {
        for (int attempt = 0; attempt < 2; attempt++) {
            try (Peer peer = new Peer((in, out) -> {
                reply(out, new Message(MessageType.ACK, "Kayıt başarılı"));
                check(in.readObject().equals(new Message(MessageType.TEXT, TEXT)), "Yeniden gönderim başarısız");
                // Sunucu bağlantıyı kapatır.
            })) {
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
            } catch (IllegalArgumentException expected) {
                // Ağa erişmeden reddedilmeli.
            }
        }
        try (Client2Connection ignored = Client2Connection.connect(" ", 5000, new Events())) {
            throw new AssertionError("Boş sunucu adresi kabul edildi");
        } catch (IllegalArgumentException expected) {
            // Ağa erişmeden reddedilmeli.
        }
    }

    private static void reply(ObjectOutputStream out, Object value) throws IOException {
        out.writeObject(value);
        out.flush();
    }

    private static void expectEof(ObjectInputStream in) throws Exception {
        try {
            in.readObject();
            throw new AssertionError("İstemci soketi kapatmadı");
        } catch (EOFException expected) {
            // Kaynaklar serbest bırakıldı.
        }
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
