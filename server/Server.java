// src/server/Server

package server ;

import common.Message ;
import common.MessageType ;

import javax.crypto.Cipher ;
import javax.crypto.SecretKey ;
import javax.crypto.spec.IvParameterSpec ;
import java.io.IOException ;
import java.io.ObjectInputStream ;
import java.io.ObjectOutputStream ;
import java.net.ServerSocket ;
import java.net.Socket ;
import java.security.SecureRandom ;
import java.util.concurrent.ConcurrentHashMap ;

public class Server {

    private static final int PORT = 5000 ;

    // Her istemcinin veri akışını ve ona özel AES anahtarını tek bir nesnede tutmak için yardımcı sınıf
    private static class ClientSession {

        final ObjectOutputStream out ;
        SecretKey aesKey ;

        ClientSession(ObjectOutputStream out) {

            this.out = out ;

        }

    }

    // Bağlı clientleri, streamleri ve AES anahtarlarını tutmak için Hashmap
    private static final ConcurrentHashMap<String , ClientSession> clients = new ConcurrentHashMap<>() ;

    public static void main(String[] args) {

        System.out.println("[DİNLENİYOR] Sunucu " + PORT + " portunda başlatıldı...") ;

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {

            while (true) {

                Socket clientSocket = serverSocket.accept() ;
                System.out.println("[YENİ BAĞLANTI] " + clientSocket.getInetAddress() + " bağlandı.") ;

                // Virtual Threads
                Thread.startVirtualThread(() -> handleClient(clientSocket)) ;

            }

        } catch (IOException e) {

            e.printStackTrace() ;

        }

    }

    private static void handleClient(Socket socket) {

        // Thread'in yönettiği istemcinin kimliği
        String currentClientId = null ; 

        // TCP bağlantısı üzerinden nesne okuma/yazma akışları
        try (

            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()) ;
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream())

        ) {

            while (true) {

                // İstemciden gelen mesajı bekle ve oku
                Message message = (Message) in.readObject() ;
                System.out.println("[" + socket.getInetAddress() + "] Gelen Mesaj Tipi: " + message.type()) ;

                // Modern Switch Expression
                switch (message.type()) {

                    case REGISTER -> {

                        currentClientId = (String) message.payload() ;
                        clients.put(currentClientId, new ClientSession(out)) ;
                        System.out.println("[KAYIT] Kullanıcı kaydedildi: " + currentClientId) ;

                        // Başarılı kayıttan sonra ACK gönder
                        out.writeObject(new Message(MessageType.ACK, "Kayıt başarılı.")) ;
                        out.flush() ;

                    }

                    case KEY_EXCHANGE -> {

                        // TODO: Diffie-Hellman / RSA / ML-KEM anahtar değişim mantığı
                        // Yapıldığında istemciye ait AES anahtarını ClientSession içine kaydedilmeli :
                        // clients.get(currentClientId).aesKey = uretilenAESAnahtari ;

                    }

                    case TEXT -> {

                        if (currentClientId == null) break ;

                        String targetId = message.targetId() ;
                        ClientSession senderSession = clients.get(currentClientId) ;
                        ClientSession targetSession = clients.get(targetId) ;

                        if (targetSession == null) {

                            System.out.println("[HATA] Hedef bulunamadı: " + targetId) ;
                            break ;

                        }

                        // Yönlendirme ve Yeniden Şifreleme Mekanizması
                        try {

                            byte[] encryptedPayload = (byte[]) message.payload() ;
                            byte[] senderIv = message.iv() ;

                            // Gönderenin AES anahtarı ile şifreyi çöz
                            byte[] decryptedData = decryptData(encryptedPayload , senderSession.aesKey , senderIv) ;

                            // Hedefin AES anahtarı ile yeniden şifrele
                            byte[] newIv = generateIv();
                            byte[] reEncryptedData = encryptData(decryptedData , targetSession.aesKey , newIv) ;

                            // Hedefe ilet
                            Message forwardMsg = new Message(MessageType.TEXT , currentClientId , targetId , reEncryptedData , newIv) ;
                            targetSession.out.writeObject(forwardMsg) ;
                            targetSession.out.flush() ;

                            System.out.println("[YÖNLENDİRME] " + currentClientId + " -> " + targetId + " başarıyla iletildi.") ;

                        } catch (Exception e) {

                            System.out.println("[KRİPTO HATASI] Mesaj işlenemedi: " + e.getMessage()) ;

                        }

                    }

                    case FILE_START, FILE_CHUNK, FILE_END -> {

                        // TODO: Dosya transfer mantığı (Metin ile aynı şifre çözme/şifreleme adımlarını içermeli)

                    }

                    default -> {

                        out.writeObject(new Message(MessageType.ERROR , "Bilinmeyen istek.")) ;
                        out.flush() ;

                    }

                }

            }

        } catch (Exception e) {

            System.out.println("[BAĞLANTI KESİLDİ] İstemci ayrıldı. Sebep: " + e.getMessage()) ;

        } finally {

            if (currentClientId != null) {
                clients.remove(currentClientId) ;
                System.out.println("[SİLİNDİ] " + currentClientId + " sistemden kaldırıldı.") ;
            }

        }

    }

    // --- Kriptografik Yardımcı Metotlar ---

    private static byte[] decryptData(byte[] data , SecretKey key , byte[] iv) throws Exception {

        if (key == null) throw new IllegalStateException("AES anahtarı henüz kurulmamış") ;
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding") ;
        cipher.init(Cipher.DECRYPT_MODE , key , new IvParameterSpec(iv)) ;
        return cipher.doFinal(data) ;

    }

    private static byte[] encryptData(byte[] data , SecretKey key , byte[] iv) throws Exception {

        if (key == null) throw new IllegalStateException("AES anahtarı henüz kurulmamış") ;
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding") ;
        cipher.init(Cipher.ENCRYPT_MODE , key , new IvParameterSpec(iv)) ;
        return cipher.doFinal(data) ;

    }

    private static byte[] generateIv() {

        byte[] iv = new byte[16] ;
        new SecureRandom().nextBytes(iv) ;
        return iv ;

    }

}