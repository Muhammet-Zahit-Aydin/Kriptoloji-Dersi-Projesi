package tests;

import client2.Client2Connection;
import common.Message;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/** Değiştirilmemiş gerçek sunucu ile Client-1'in mevcut UTF biçimini doğrular. */
public final class InsecureTextIntegrationTest {
    public static void main(String[] args) throws Exception {
        // 5000 doluysa mevcut sürece dokunmadan testi durdur.
        try (ServerSocket probe = new ServerSocket(5000)) { }
        String java = Path.of(System.getProperty("java.home"), "bin", "java.exe").toString();
        Process server = new ProcessBuilder(java, "-Dstdout.encoding=UTF-8", "-cp",
                System.getProperty("java.class.path"), "server.Server")
                .redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        try {
            waitForServer(server);
            BlockingQueue<String> client2Messages = new LinkedBlockingQueue<>();
            Client2Connection.Listener listener = new Client2Connection.Listener() {
                public void onMessage(Message message) { client2Messages.add((String) message.payload()); }
                public void onDisconnected(String reason) { }
            };
            try (Socket client1 = new Socket("127.0.0.1", 5000)) {
                // Aynı akış sırası ve aynı UTF çağrıları client1.Client1 içinde kullanılır.
                ObjectOutputStream out = new ObjectOutputStream(client1.getOutputStream());
                out.flush();
                ObjectInputStream in = new ObjectInputStream(client1.getInputStream());
                BlockingQueue<String> client1Messages = new LinkedBlockingQueue<>();
                Thread.startVirtualThread(() -> {
                    try { while (!client1.isClosed()) client1Messages.add(in.readUTF()); }
                    catch (IOException expectedOnClose) { }
                });
                for (int attempt = 0; attempt < 2; attempt++) {
                    try (Client2Connection client2 = Client2Connection.connect("127.0.0.1", 5000, listener)) {
                        client2.startReceiving();
                        // Sunucu ACK göndermediği için iki soketin listede olmasını veriyle doğrula.
                        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
                        while (true) {
                            client2.sendText("SYNC");
                            if ("SYNC".equals(client1Messages.poll(100, TimeUnit.MILLISECONDS))) break;
                            if (System.nanoTime() > deadline) throw new AssertionError("Yönlendirme hazır olmadı");
                        }
                        String toClient1 = "Client2 → Client1: ığüşöç İĞÜŞÖÇ 👋\n" + attempt;
                        client2.sendText(toClient1);
                        expect(client1Messages, toClient1);
                        String toClient2 = "Client1 → Client2: ığüşöç İĞÜŞÖÇ\n" + attempt;
                        out.writeUTF(toClient2);
                        out.flush();
                        expect(client2Messages, toClient2);
                    }
                }
            }
            System.out.println("PASS: Actual server.Server, Client-1 UTF compatibility, bidirectional text and reconnect.");
        } finally {
            server.destroy();
            if (!server.waitFor(3, TimeUnit.SECONDS)) server.destroyForcibly().waitFor(3, TimeUnit.SECONDS);
        }
    }

    private static void waitForServer(Process process) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (process.isAlive()) {
            try (Socket probe = new Socket()) {
                probe.connect(new InetSocketAddress("127.0.0.1", 5000), 100);
                return;
            } catch (IOException e) {
                if (System.nanoTime() > deadline) throw e;
                Thread.sleep(40);
            }
        }
        throw new AssertionError("Test sunucusu başlatılamadı.");
    }

    private static void expect(BlockingQueue<String> queue, String expected) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            String value = queue.poll(100, TimeUnit.MILLISECONDS);
            if (expected.equals(value)) return;
            if (value != null && !value.equals("SYNC")) throw new AssertionError("Metin değişti: " + value);
        }
        throw new AssertionError("Metin karşı istemciye ulaşmadı.");
    }
}
