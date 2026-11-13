package client2;

import common.crypto.AesSessionFrameCodec;
import common.crypto.EcdhUtils;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Arrays;

/** Client-2 için aynı süreçte iki rol kullanan, bağımsız ECDH doğrulaması. */
public final class EcdhLocalTest {
    private EcdhLocalTest() { }

    public static void main(String[] args) throws Exception {
        KeyPair clientKeys = EcdhUtils.generateKeyPair();
        KeyPair peerKeys = EcdhUtils.generateKeyPair();

        // Değişim sınırından yalnızca açık anahtarların DER byte dizileri geçer.
        PublicKey peerAtClient = EcdhUtils.getPublicKeyFromBytes(peerKeys.getPublic().getEncoded());
        PublicKey clientAtPeer = EcdhUtils.getPublicKeyFromBytes(clientKeys.getPublic().getEncoded());
        byte[] clientSecret = EcdhUtils.computeSharedSecret(clientKeys.getPrivate(), peerAtClient);
        byte[] peerSecret = EcdhUtils.computeSharedSecret(peerKeys.getPrivate(), clientAtPeer);
        byte[] clientAesKey = null;
        byte[] peerAesKey = null;
        try {
            if (!MessageDigest.isEqual(clientSecret, peerSecret)) {
                throw new AssertionError("Client-2 ile test eşinin ortak sırları farklı.");
            }
            clientAesKey = EcdhUtils.deriveAes128Key(clientSecret).getEncoded();
            peerAesKey = EcdhUtils.deriveAes128Key(peerSecret).getEncoded();
            if (!MessageDigest.isEqual(clientAesKey, peerAesKey)) {
                throw new AssertionError("Client-2 ile test eşinin AES anahtarları farklı.");
            }

            // Mevcut AES-GCM oturum çerçeveleri iki yönde de açılabilmelidir.
            String request = "Client-2 ECDH testi: ığüşöç İĞÜŞÖÇ 👋";
            String encryptedRequest = AesSessionFrameCodec.encode(request, clientAesKey);
            if (!request.equals(AesSessionFrameCodec.decode(encryptedRequest, peerAesKey))) {
                throw new AssertionError("Test eşi Client-2 çerçevesini açamadı.");
            }
            String reply = "Test eşinden ECDH yanıtı";
            String encryptedReply = AesSessionFrameCodec.encode(reply, peerAesKey);
            if (!reply.equals(AesSessionFrameCodec.decode(encryptedReply, clientAesKey))) {
                throw new AssertionError("Client-2 yanıt çerçevesini açamadı.");
            }

            // Anahtar ve ortak sır değerleri terminale yazdırılmaz.
            System.out.println("PASS: Client-2 local ECDH P-256 public-key encoding and exchange.");
            System.out.println("PASS: Equal shared secrets and 128-bit AES keys on both local roles.");
            System.out.println("PASS: Bidirectional AES-GCM frames with Turkish/emoji text.");
        } finally {
            Arrays.fill(clientSecret, (byte) 0);
            Arrays.fill(peerSecret, (byte) 0);
            if (clientAesKey != null) {
                Arrays.fill(clientAesKey, (byte) 0);
            }
            if (peerAesKey != null) {
                Arrays.fill(peerAesKey, (byte) 0);
            }
        }
    }
}
