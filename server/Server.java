package server ;

import common.Message ;
import common.MessageType ;

import javax.crypto.Cipher ;
import javax.crypto.SecretKey ;
import javax.crypto.spec.IvParameterSpec ;
import java.io.File ;
import java.io.FileOutputStream ;
import java.io.IOException ;
import java.io.ObjectInputStream ;
import java.io.ObjectOutputStream ;
import java.net.ServerSocket ;
import java.net.Socket ;
import java.security.SecureRandom ;
import java.util.concurrent.ConcurrentHashMap ;

public class Server {

    private static final int PORT = 5000 ;
    private static final String UPLOAD_DIR = "captures" ;

    // Her istemcinin oturumunu ve transfer durumunu tutan yapı
    private static class ClientSession {

        final ObjectOutputStream out;
        SecretKey aesKey ; 

        // Dosya transfer takibi
        String activeFileName ;
        long expectedFileSize ;
        long bytesReceived ;
        int expectedChunkIndex ;
        FileOutputStream fileOut ;

        ClientSession(ObjectOutputStream out) {

            this.out = out ;
        }

    }

    private static final ConcurrentHashMap<String , ClientSession> clients = new ConcurrentHashMap<>() ;

    public static void main(String[] args) {

        // Dosyaların kaydedileceği klasörü oluştur
        File dir = new File(UPLOAD_DIR) ;
        if (!dir.exists()) dir.mkdir() ;

        System.out.println("[DİNLENİYOR] Sunucu " + PORT + " portunda başlatıldı...") ;
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {

            while (true) {

                Socket clientSocket = serverSocket.accept() ;
                System.out.println("[YENİ BAĞLANTI] " + clientSocket.getInetAddress() + " bağlandı.") ;
                Thread.startVirtualThread(() -> handleClient(clientSocket)) ;

            }

        } catch (IOException e) {

            e.printStackTrace() ;

        }

    }

    private static void handleClient(Socket socket) {

        String currentClientId = null ;

        try (

            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream())

        ) {

            while (true) {

                Message message = (Message) in.readObject() ;
                
                switch (message.type()) {

                    case REGISTER -> {

                        currentClientId = (String) message.payload() ;
                        clients.put(currentClientId , new ClientSession(out)) ;
                        System.out.println("[KAYIT] Kullanıcı kaydedildi: " + currentClientId) ;
                        out.writeObject(new Message(MessageType.ACK , "Kayıt başarılı.")) ;
                        out.flush() ;

                    }

                    case KEY_EXCHANGE -> {

                        // TODO: Anahtar değişim mantığı. İşlem bitince:
                        // clients.get(currentClientId).aesKey = createdAESKey ;

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

                        byte[] payload = (byte[]) message.payload() ;
                        byte[] iv = message.iv() ;
                        String textContent ;
                        Message forwardMsg ;

                        // Şifreli mesaj kontrolü
                        if (iv != null && senderSession.aesKey != null && targetSession.aesKey != null) {

                            byte[] decryptedData = decryptData(payload , senderSession.aesKey , iv) ;
                            textContent = new String(decryptedData) ;

                            byte[] newIv = generateIv() ;
                            byte[] reEncryptedData = encryptData(decryptedData , targetSession.aesKey , newIv) ;
                            forwardMsg = new Message(MessageType.TEXT, currentClientId , targetId , reEncryptedData , newIv) ;
                            System.out.println("[GÜVENLİ METİN] Çözüldü -> " + currentClientId + ": " + textContent) ;

                        } else {

                            textContent = new String(payload) ;
                            forwardMsg = new Message(MessageType.TEXT, currentClientId , targetId , payload , null) ;
                            System.out.println("[GÜVENSİZ METİN] " + currentClientId + ": " + textContent) ;

                        }

                        targetSession.out.writeObject(forwardMsg) ;
                        targetSession.out.flush() ;

                    }

                    case FILE_START -> {

                        String targetId = message.targetId() ;
                        ClientSession senderSession = clients.get(currentClientId) ;
                        ClientSession targetSession = clients.get(targetId) ;
                        
                        // Payload "dosyaadi.pdf;boyut" formatında geldiği varsayılmıştır
                        String fileInfo = (String) message.payload() ;
                        String[] parts = fileInfo.split(";") ;
                        String filename = parts[0] ;
                        long size = parts.length > 1 ? Long.parseLong(parts[1]) : -1 ;

                        if (!isValidFilename(filename)) {

                            System.out.println("[GÜVENLİK İHLALİ] Geçersiz dosya yolu engellendi: " + filename) ;
                            break ;

                        }

                        senderSession.activeFileName = filename ;
                        senderSession.expectedFileSize = size ;
                        senderSession.bytesReceived = 0 ;
                        senderSession.expectedChunkIndex = 0 ;
                        
                        File destFile = new File(UPLOAD_DIR, filename) ;
                        senderSession.fileOut = new FileOutputStream(destFile) ;
                        System.out.println("[DOSYA TRANSFERİ BAŞLADI] " + filename + " (Boyut: " + size + " byte)") ;

                        if (targetSession != null) {

                            targetSession.out.writeObject(message) ;
                            targetSession.out.flush() ;

                        }

                    }

                    case FILE_CHUNK -> {

                        String targetId = message.targetId() ;
                        ClientSession senderSession = clients.get(currentClientId) ;
                        ClientSession targetSession = clients.get(targetId) ;

                        if (senderSession == null || senderSession.fileOut == null) break ;

                        byte[] chunk = (byte[]) message.payload(); 
                        byte[] iv = message.iv() ;
                        Message forwardMsg ;

                        // Şifreli chunk çözümü
                        if (iv != null && senderSession.aesKey != null) {

                            chunk = decryptData(chunk , senderSession.aesKey , iv) ;

                        }

                        // Sunucuya kaydet ve sıra/boyut sayacını güncelle
                        senderSession.fileOut.write(chunk) ;
                        senderSession.bytesReceived += chunk.length ;
                        senderSession.expectedChunkIndex++ ;

                        if (targetSession != null) {

                            // Hedefe yönlendir
                            if (iv != null && targetSession.aesKey != null) {

                                byte[] newIv = generateIv() ;
                                byte[] reEncryptedChunk = encryptData(chunk , targetSession.aesKey , newIv) ;
                                forwardMsg = new Message(MessageType.FILE_CHUNK , currentClientId , targetId , reEncryptedChunk , newIv) ;

                            } else {

                                forwardMsg = new Message(MessageType.FILE_CHUNK, currentClientId , targetId , chunk , null) ;

                            }

                            targetSession.out.writeObject(forwardMsg) ;
                            targetSession.out.flush() ;

                        }

                    }

                    case FILE_END -> {

                        String targetId = message.targetId() ;
                        ClientSession senderSession = clients.get(currentClientId) ;
                        ClientSession targetSession = clients.get(targetId) ;

                        if (senderSession != null && senderSession.fileOut != null) {

                            senderSession.fileOut.close() ;
                            System.out.println("[DOSYA TAMAMLANDI] " + senderSession.activeFileName + " başarıyla sunucuya kaydedildi.") ;

                            
                            // Boyut doğrulaması
                            if (senderSession.expectedFileSize != -1 && senderSession.bytesReceived != senderSession.expectedFileSize) {

                                System.out.println("[UYARI] Dosya boyutu uyumsuz! Beklenen: " + senderSession.expectedFileSize + ", Alınan: " + senderSession.bytesReceived) ;

                            }
                            
                            // State sıfırla
                            senderSession.fileOut = null ;

                        }

                        if (targetSession != null) {

                            targetSession.out.writeObject(message) ;
                            targetSession.out.flush() ;

                        }

                    }

                    default -> {

                        out.writeObject(new Message(MessageType.ERROR , "Bilinmeyen istek.")) ;
                        out.flush() ;

                    }

                }

            }

        } catch (Exception e) {

            System.out.println("[BAĞLANTI KESİLDİ] " + currentClientId + " ayrıldı. Sebep: " + e.getMessage()) ;

        } finally {

            if (currentClientId != null) {

                clients.remove(currentClientId) ;

            }

        }

    }

    // Klasör dışına çıkmayı hedefleyen path traversal zafiyetini engeller
    private static boolean isValidFilename(String filename) {

        if (filename == null || filename.isBlank()) return false ;
        return !filename.contains("..") && !filename.contains("/") && !filename.contains("\\") ;

    }

    private static byte[] decryptData(byte[] data , SecretKey key , byte[] iv) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding") ;
        cipher.init(Cipher.DECRYPT_MODE , key , new IvParameterSpec(iv)) ;
        return cipher.doFinal(data) ;

    }

    private static byte[] encryptData(byte[] data , SecretKey key , byte[] iv) throws Exception {
        
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