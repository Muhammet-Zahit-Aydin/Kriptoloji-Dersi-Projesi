package tests;

import client2.Client2Connection;
import common.Message;
import common.MessageType;
import common.FileTransfer;
import common.FileTransferReceiver;
import common.FileTransferSender;
import common.SecureFrameCodec;
import common.crypto.CryptoMode;
import common.crypto.AesSessionFrameCodec;
import common.crypto.SessionHandshake;
import common.crypto.KeyExchangeMethod;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Locale;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/** Gerçek sunucu ve Client-1'in kullandığı ortak bileşenlerle Client-2 entegrasyonu. */
public final class InsecureTextIntegrationTest {
    private static final String TEST_PASSWORD = "yalnızca-entegrasyon-testi";

    public static void main(String[] args) throws Exception {
        // 5000 doluysa mevcut sürece dokunmadan testi durdur.
        try (ServerSocket probe = new ServerSocket(5000)) { }
        Path directory = Files.createTempDirectory("client2-integration-");
        String java = Path.of(System.getProperty("java.home"), "bin", "java.exe").toString();
        Process server = new ProcessBuilder(java, "-Dstdout.encoding=UTF-8",
                "-Dkriptoloji.server.files=" + directory.resolve("server"), "-cp",
                System.getProperty("java.class.path"), "server.Server")
                .redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        try {
            waitForServer(server);
            BlockingQueue<String> client2Messages = new LinkedBlockingQueue<>();
            BlockingQueue<FileTransferReceiver.ReceivedFile> client2Files = new LinkedBlockingQueue<>();
            Client2Connection.Listener listener = new Client2Connection.Listener() {
                public void onMessage(Message message) { client2Messages.add((String) message.payload()); }
                public void onDisconnected(String reason) { }
                public void onFileReceived(FileTransferReceiver.ReceivedFile file) { client2Files.add(file); }
            };
            for (KeyExchangeMethod client1Method : KeyExchangeMethod.values()) {
                try (Socket client1 = new Socket("127.0.0.1", 5000)) {
                    // Aynı akış sırası ve aynı UTF çağrıları client1.Client1 içinde kullanılır.
                    ObjectOutputStream out = new ObjectOutputStream(client1.getOutputStream());
                    out.flush();
                    ObjectInputStream in = new ObjectInputStream(client1.getInputStream());
                    byte[] client1SessionKey = SessionHandshake.connect(in, out, "Client1", client1Method);
                    BlockingQueue<String> client1Messages = new LinkedBlockingQueue<>();
                    Set<String> client1FileNonces = ConcurrentHashMap.newKeySet();
                    Thread.startVirtualThread(() -> {
                        try {
                            while (!client1.isClosed()) {
                                String wireFrame = in.readUTF();
                                if (!AesSessionFrameCodec.isSessionFrame(wireFrame))
                                    throw new IOException("PDF paketi AES-GCM oturum zarfında değil.");
                                String applicationFrame = AesSessionFrameCodec.decode(wireFrame, client1SessionKey);
                                Message received = SecureFrameCodec.validateForRelay(applicationFrame);
                                if (received != null && isFilePacket(received.type()))
                                    client1FileNonces.add(sessionNonce(wireFrame));
                                client1Messages.add(applicationFrame);
                            }
                        }
                        catch (IOException expectedOnClose) { }
                    });
                    CryptoMode[] modes = {CryptoMode.INSECURE, CryptoMode.INSECURE,
                            CryptoMode.AES_128_GCM, CryptoMode.AES_128_CBC_MANUAL};
                    for (int attempt = 0; attempt < modes.length; attempt++) {
                        CryptoMode mode = modes[attempt];
                        KeyExchangeMethod client2Method = KeyExchangeMethod.values()[attempt % 2];
                        try (Client2Connection client2 = Client2Connection.connect("127.0.0.1", 5000, listener,
                                mode, TEST_PASSWORD, client2Method)) {
                            client2.startReceiving();
                            // ACK sonrasında iki oturumun yönlendirmeye katıldığını doğrula.
                            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
                            while (true) {
                                client2.sendText("SYNC");
                                String frame = client1Messages.poll(100, TimeUnit.MILLISECONDS);
                                if (frame != null && "SYNC".equals(SecureFrameCodec.decode(frame, TEST_PASSWORD).payload())) break;
                                if (System.nanoTime() > deadline) throw new AssertionError("Yönlendirme hazır olmadı");
                            }
                            String toClient1 = "Client2 → Client1: ığüşöç İĞÜŞÖÇ 👋\n" + attempt;
                            client2.sendText(toClient1);
                            expect(client1Messages, toClient1);
                            String toClient2 = "Client1 → Client2: ığüşöç İĞÜŞÖÇ\n" + attempt;
                            String applicationFrame = SecureFrameCodec.encode(
                                    new Message(MessageType.TEXT, "Client1", "Client2", toClient2, null), mode, TEST_PASSWORD);
                            out.writeUTF(AesSessionFrameCodec.encode(applicationFrame, client1SessionKey));
                            out.flush();
                            expect(client2Messages, toClient2);
                            // Dört RSA/DH eşleşmesinin her birinde AES ile korunan PDF taşı.
                            if (attempt >= 2) {
                                String label = client1Method.name() + "-" + client2Method.name() + "-" + mode.name();
                                pdfRoundTrips(client2, out, client1SessionKey, client1Messages, client2Files,
                                        client1FileNonces, directory, label);
                            }
                        }
                    }
                }
            }
            System.out.println("PASS: Actual server.Server, Client-1 UTF compatibility, bidirectional text and reconnect.");
            System.out.println("PASS: Actual server relay, bidirectional AES-GCM and manual AES-CBC text.");
            System.out.println("PASS: RSA/RSA, RSA/DH, DH/RSA and DH/DH sessions with bidirectional text.");
            System.out.println("PASS: Both PDF directions and server disk copies across every RSA/DH pairing.");
            System.out.println("PASS: File frames use fresh AES-GCM session nonces and reach authenticated receivers.");
            rejectInvalidServerTransfer(directory);
        } finally {
            server.destroy();
            if (!server.waitFor(3, TimeUnit.SECONDS)) server.destroyForcibly().waitFor(3, TimeUnit.SECONDS);
            try (var paths = Files.walk(directory)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
            }
        }
    }

    private static void pdfRoundTrips(Client2Connection client2, ObjectOutputStream client1Out, byte[] client1SessionKey,
            BlockingQueue<String> frames, BlockingQueue<FileTransferReceiver.ReceivedFile> files,
            Set<String> incomingFileNonces, Path directory, String label) throws Exception {
        Path source = directory.resolve("Türkçe belge.pdf");
        Files.write(source, pdfBytes());
        int expectedPackets = 2 + (int) ((Files.size(source) + FileTransfer.CHUNK_SIZE - 1) / FileTransfer.CHUNK_SIZE);
        int nonceCountBefore = incomingFileNonces.size();
        ArrayList<Long> progress = new ArrayList<>();
        client2.sendPdf(source, (metadata, bytes) -> progress.add(bytes));
        if (progress.getFirst() != 0 || progress.getLast() != Files.size(source))
            throw new AssertionError("Client-2 gönderim ilerlemesi tamamlanmadı");
        try (FileTransferReceiver receiver = new FileTransferReceiver()) {
            while (true) {
            Message message = SecureFrameCodec.decode(take(frames));
                switch (message.type()) {
                    case FILE_START -> receiver.start((FileTransfer.Start) message.payload());
                    case FILE_CHUNK -> receiver.append((FileTransfer.Chunk) message.payload());
                    case FILE_END -> {
                        try (var received = receiver.finish((FileTransfer.End) message.payload())) {
                            compareCopies(source, received, directory, label + "-Client2-to-Client1");
                        }
                    }
                    default -> throw new AssertionError("Beklenmeyen PDF paketi: " + message.type());
                }
                if (message.type() == MessageType.FILE_END) break;
            }
        }
        if (incomingFileNonces.size() - nonceCountBefore != expectedPackets)
            throw new AssertionError("Sunucudan alıcıya yönlenen her PDF paketi için yeni AES-GCM nonce görülmedi");

        // Client-1 aynı FILE_* sözleşmesini kullanır; her paketi oturum AES-GCM ile sarar.
        Set<String> outgoingFileNonces = new java.util.HashSet<>();
        FileTransfer.Start metadata = FileTransferSender.inspect(source);
        FileTransferSender.send(source, metadata, "Client1", "Client2", packet -> {
            String wireFrame = AesSessionFrameCodec.encode(SecureFrameCodec.encode(packet), client1SessionKey);
            if (!AesSessionFrameCodec.isSessionFrame(wireFrame) || !outgoingFileNonces.add(sessionNonce(wireFrame)))
                throw new IOException("İstemci PDF paketi AES-GCM ile korunmadı veya nonce tekrarlandı");
            client1Out.writeUTF(wireFrame);
            client1Out.flush();
        }, bytes -> { });
        if (outgoingFileNonces.size() != expectedPackets)
            throw new AssertionError("Client-1'in her PDF paketi için yeni AES-GCM nonce üretilmedi");
        try (var received = take(files)) {
            compareCopies(source, received, directory, label + "-Client1-to-Client2");
        }
    }

    private static void compareCopies(Path source, FileTransferReceiver.ReceivedFile received,
            Path directory, String direction) throws Exception {
        Path destination = directory.resolve(direction + ".pdf");
        received.saveTo(destination);
        Path serverCopy = directory.resolve("server").resolve(received.metadata().fileId() + ".pdf");
        String expected = sha256(source);
        for (Path copy : new Path[] {serverCopy, destination}) {
            if (Files.size(copy) != Files.size(source) || Files.mismatch(source, copy) != -1 || !sha256(copy).equals(expected))
                throw new AssertionError(direction + ": boyut, byte içeriği veya SHA-256 farklı");
        }
        System.out.println("PASS: " + direction + " PDF; source/server/receiver bytes=" + Files.size(source)
                + ", SHA-256=" + expected);
    }

    private static boolean isFilePacket(MessageType type) {
        return type == MessageType.FILE_START || type == MessageType.FILE_CHUNK || type == MessageType.FILE_END;
    }

    // Oturum zarfının ilk 12 byte'ı GCM nonce'dir; FILE_* mesajlarında tekrar ararız.
    private static String sessionNonce(String wireFrame) throws IOException {
        if (!AesSessionFrameCodec.isSessionFrame(wireFrame)) throw new IOException("AES-GCM oturum zarfı eksik.");
        byte[] body;
        try { body = java.util.Base64.getDecoder().decode(wireFrame.substring("\u001eKRIPTO1S:".length())); }
        catch (IllegalArgumentException e) { throw new IOException("AES-GCM zarfı bozuk.", e); }
        if (body.length < 12 + 16) throw new IOException("AES-GCM nonce/tag eksik.");
        return HexFormat.of().formatHex(java.util.Arrays.copyOf(body, 12));
    }

    private static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(path)) {
            byte[] buffer = new byte[8192];
            int length;
            while ((length = input.read(buffer)) != -1) digest.update(buffer, 0, length);
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void rejectInvalidServerTransfer(Path directory) throws Exception {
        try (Socket socket = new Socket("127.0.0.1", 5000)) {
            socket.setSoTimeout(5000);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            out.flush();
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            byte[] sessionKey = SessionHandshake.connect(in, out, "Client1", KeyExchangeMethod.RSA_2048);
            var metadata = new FileTransfer.Start(java.util.UUID.randomUUID(), "invalid.pdf", 100);
            out.writeUTF(AesSessionFrameCodec.encode(SecureFrameCodec.encode(new Message(MessageType.FILE_START,
                    "Client1", "Client2", metadata, null)), sessionKey));
            out.writeUTF(AesSessionFrameCodec.encode(SecureFrameCodec.encode(new Message(MessageType.FILE_CHUNK,
                    "Client1", "Client2", new FileTransfer.Chunk(metadata.fileId(), 1, new byte[] {1}), null)), sessionKey));
            out.flush();
            try { in.readUTF(); throw new AssertionError("Sunucu sırasız parçayı kabul etti"); }
            catch (java.io.EOFException expected) { }
            if (Files.exists(directory.resolve("server").resolve(metadata.fileId() + ".pdf")))
                throw new AssertionError("Geçersiz PDF tamamlanmış olarak kaydedildi");
        }
        System.out.println("PASS: Server rejected out-of-order PDF without publishing a completed copy.");
    }

    /** Üçten fazla parçaya bölünen, tek sayfalık geçerli PDF test belgesi. */
    private static byte[] pdfBytes() {
        String content = "BT /F1 12 Tf 50 750 Td (Client-2 PDF integration) Tj ET\n" + "% padding\n".repeat(6000);
        String[] objects = {"<< /Type /Catalog /Pages 2 0 R >>",
                "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
                "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
                "<< /Length " + content.length() + " >>\nstream\n" + content + "endstream"};
        StringBuilder pdf = new StringBuilder("%PDF-1.4\n");
        StringBuilder xref = new StringBuilder("xref\n0 6\n0000000000 65535 f \n");
        for (int i = 0; i < objects.length; i++) {
            xref.append(String.format(Locale.ROOT, "%010d 00000 n \n", pdf.length()));
            pdf.append(i + 1).append(" 0 obj\n").append(objects[i]).append("\nendobj\n");
        }
        int offset = pdf.length();
        return pdf.append(xref).append("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n")
                .append(offset).append("\n%%EOF\n").toString().getBytes(StandardCharsets.US_ASCII);
    }

    private static <T> T take(BlockingQueue<T> queue) throws InterruptedException {
        T value = queue.poll(8, TimeUnit.SECONDS);
        if (value == null) throw new AssertionError("Beklenen ağ olayı zamanında gelmedi");
        return value;
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
            // Client-2 kuyruğu çözülmüş metin, Client-1 kuyruğu UTF çerçevesi taşır.
            if (value != null && value.startsWith("\u001eKRIPTO1:")) {
                try { value = (String) SecureFrameCodec.decode(value, TEST_PASSWORD).payload(); }
                catch (IOException e) { throw new AssertionError("Client-1 AES metnini çözemedi", e); }
            }
            if (expected.equals(value)) return;
            if (value != null && !value.equals("SYNC")) throw new AssertionError("Metin değişti: " + value);
        }
        throw new AssertionError("Metin karşı istemciye ulaşmadı.");
    }
}
