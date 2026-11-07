package tests;

import client2.Client2Connection;
import common.Message;
import common.MessageType;
import common.SecureFrameCodec;
import common.crypto.AesSessionFrameCodec;
import common.crypto.DiffieHellmanUtils;
import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;

/** DH anahtar eşitliği, ağdaki açık paketler ve ACK sınırı ayrı ayrı doğrulanır. */
public final class DhSessionHandshakeTest {
    private static final Client2Connection.Listener LISTENER = new Client2Connection.Listener() {
        public void onMessage(Message message) { }
        public void onDisconnected(String reason) { }
    };

    public static void main(String[] args) throws Exception {
        parametersAndDerivation();
        byte[] first = exchangeWithDelayedAck();
        byte[] second = exchangeWithDelayedAck();
        check(!Arrays.equals(first, second), "Yeniden bağlantıda DH anahtarı yenilenmedi");
        rejectedHandshakes();
        System.out.println("PASS: DH-2048 group validation and SHA-256-to-AES-128 derivation.");
        System.out.println("PASS: Client-2/server AES key agreement, fresh sessions, public-key-only exchange and ACK gating.");
        System.out.println("PASS: DH rejected invalid public key, failed ACK and unexpected ACK packet.");
    }

    private static void parametersAndDerivation() throws Exception {
        KeyPair client = DiffieHellmanUtils.generateDHKeyPair();
        KeyPair server = DiffieHellmanUtils.generateDHKeyPair();
        DHPublicKey publicKey = (DHPublicKey) client.getPublic();
        check(publicKey.getParams().getP().bitLength() == 2048, "DH grubu 2048 bit değil");
        byte[] clientSecret = DiffieHellmanUtils.computeSharedSecret(client.getPrivate(), server.getPublic());
        byte[] serverSecret = DiffieHellmanUtils.computeSharedSecret(server.getPrivate(), client.getPublic());
        check(Arrays.equals(clientSecret, serverSecret), "Ortak sırlar farklı");
        byte[] expected = Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(clientSecret), 16);
        check(Arrays.equals(expected, DiffieHellmanUtils.deriveAes128Key(serverSecret).getEncoded()),
                "AES anahtarı belgelenen türetmeyle eşleşmedi");

        for (var invalid : new java.math.BigInteger[] {java.math.BigInteger.ONE,
                publicKey.getParams().getP().subtract(java.math.BigInteger.TWO)}) {
            try {
                var key = KeyFactory.getInstance("DH").generatePublic(new DHPublicKeySpec(
                        invalid, publicKey.getParams().getP(), publicKey.getParams().getG()));
                DiffieHellmanUtils.getPublicKeyFromBytes(key.getEncoded());
                throw new AssertionError("Geçersiz DH açık değeri kabul edildi");
            } catch (java.security.GeneralSecurityException expectedFailure) { }
        }

        // Başka bir DH grubu, geçerli DER kodlamasına sahip olsa bile kabul edilmemeli.
        KeyPairGenerator smaller = KeyPairGenerator.getInstance("DH");
        smaller.initialize(1024);
        try {
            DiffieHellmanUtils.getPublicKeyFromBytes(smaller.generateKeyPair().getPublic().getEncoded());
            throw new AssertionError("1024 bit DH anahtarı kabul edildi");
        } catch (java.security.GeneralSecurityException expectedFailure) { }
    }

    private static byte[] exchangeWithDelayedAck() throws Exception {
        CountDownLatch clientKeyArrived = new CountDownLatch(1);
        CountDownLatch allowAck = new CountDownLatch(1);
        CompletableFuture<byte[]> serverResult = new CompletableFuture<>();
        ArrayList<Message> wirePackets = new ArrayList<>();
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Thread.startVirtualThread(() -> {
                try (Socket socket = listener.accept()) {
                    socket.setSoTimeout(5000);
                    ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                    out.flush();
                    ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                    Message selection = SecureFrameCodec.decode(in.readUTF());
                    wirePackets.add(selection);
                    check(selection.type() == MessageType.KEY_EXCHANGE_INIT, "Yöntem seçimi eksik");
                    check(Arrays.equals((byte[]) selection.payload(), "DH_2048".getBytes(java.nio.charset.StandardCharsets.US_ASCII)),
                            "DH-2048 seçilmedi");

                    KeyPair serverKeys = DiffieHellmanUtils.generateDHKeyPair();
                    Message publicKey = new Message(MessageType.DH_PUB_KEY_EXCHANGE, serverKeys.getPublic().getEncoded());
                    wirePackets.add(publicKey);
                    out.writeUTF(SecureFrameCodec.encode(publicKey));
                    out.flush();
                    Message clientKey = SecureFrameCodec.decode(in.readUTF());
                    wirePackets.add(clientKey);
                    check(clientKey.type() == MessageType.DH_PUB_KEY_EXCHANGE, "DH açık anahtarı yerine başka veri geldi");
                    byte[] secret = DiffieHellmanUtils.computeSharedSecret(serverKeys.getPrivate(),
                            DiffieHellmanUtils.getPublicKeyFromBytes((byte[]) clientKey.payload()));
                    byte[] key = DiffieHellmanUtils.deriveAes128Key(secret).getEncoded();
                    for (Message packet : wirePackets) {
                        check(!Arrays.equals(key, (byte[]) packet.payload()), "AES anahtarı ağdan doğrudan gönderildi");
                    }
                    clientKeyArrived.countDown();
                    check(allowAck.await(5, TimeUnit.SECONDS), "Test ACK izni gelmedi");
                    out.writeUTF(SecureFrameCodec.encode(new Message(MessageType.HANDSHAKE_SUCCESS, new byte[0])));
                    out.flush();

                    // Sunucu, gerçek Client-2'nin AES-GCM çerçevesini kendi türettiği anahtarla açabilmeli.
                    String text = AesSessionFrameCodec.decode(in.readUTF(), key);
                    check("DH ile Türkçe: ığüşöç 👋".equals(SecureFrameCodec.decode(text).payload()),
                            "Client-2 ve sunucunun AES anahtarları farklı");
                    serverResult.complete(key);
                    expectEof(in);
                } catch (Throwable e) {
                    serverResult.completeExceptionally(e);
                    clientKeyArrived.countDown();
                }
            });

            CompletableFuture<Client2Connection> connecting = new CompletableFuture<>();
            Thread.startVirtualThread(() -> {
                try { connecting.complete(Client2Connection.connect("127.0.0.1", listener.getLocalPort(), LISTENER)); }
                catch (Throwable e) { connecting.completeExceptionally(e); }
            });
            try {
                check(clientKeyArrived.await(5, TimeUnit.SECONDS), "İstemci DH anahtarı gelmedi");
                try {
                    connecting.get(150, TimeUnit.MILLISECONDS);
                    throw new AssertionError("ACK gelmeden bağlantı gönderime açıldı");
                } catch (TimeoutException expected) { }
                allowAck.countDown();
                try (Client2Connection connection = connecting.get(5, TimeUnit.SECONDS)) {
                    connection.sendText("DH ile Türkçe: ığüşöç 👋");
                    return serverResult.get(5, TimeUnit.SECONDS);
                }
            } finally {
                allowAck.countDown();
            }
        }
    }

    private static void rejectedHandshakes() throws Exception {
        for (int scenario = 0; scenario < 3; scenario++) {
            final int failure = scenario;
            CompletableFuture<Void> finished = new CompletableFuture<>();
            try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
                Thread.startVirtualThread(() -> {
                    try (Socket socket = listener.accept()) {
                        socket.setSoTimeout(5000);
                        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                        out.flush();
                        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                        SecureFrameCodec.decode(in.readUTF()); // Yöntem seçimi.
                        byte[] key = failure == 2 ? new byte[] {1}
                                : DiffieHellmanUtils.generateDHKeyPair().getPublic().getEncoded();
                        out.writeUTF(SecureFrameCodec.encode(new Message(MessageType.DH_PUB_KEY_EXCHANGE, key)));
                        out.flush();
                        if (failure != 2) {
                            SecureFrameCodec.decode(in.readUTF()); // İstemcinin açık anahtarı.
                            MessageType response = failure == 0 ? MessageType.HANDSHAKE_FAILED : MessageType.TEXT;
                            out.writeUTF(SecureFrameCodec.encode(new Message(response,
                                    failure == 0 ? new byte[0] : "ACK değil")));
                            out.flush();
                        }
                        expectEof(in);
                        finished.complete(null);
                    } catch (Throwable e) { finished.completeExceptionally(e); }
                });
                try (Client2Connection ignored = Client2Connection.connect("127.0.0.1", listener.getLocalPort(), LISTENER)) {
                    throw new AssertionError("Başarısız DH el sıkışması kabul edildi");
                } catch (IOException expected) { }
                finished.get(5, TimeUnit.SECONDS);
            }
        }
    }

    private static void expectEof(ObjectInputStream in) throws IOException {
        try {
            in.readUTF();
            throw new AssertionError("Başarısız/kapalı oturum veri göndermeyi sürdürdü");
        } catch (EOFException expected) { }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
