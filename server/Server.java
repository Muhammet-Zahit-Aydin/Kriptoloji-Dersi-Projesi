// src/server/Server.java
package server ;

import common.Message ;
import common.MessageType ;

import java.io.IOException ;
import java.io.ObjectInputStream ;
import java.io.ObjectOutputStream ;
import java.net.ServerSocket ;
import java.net.Socket ;
import java.util.concurrent.ConcurrentHashMap ;

public class Server {

    private static final int PORT = 5000 ;

    // Bağlı clientleri ve streamleri Map'te tutuyoruz
    private static final ConcurrentHashMap<String, ObjectOutputStream> clients = new ConcurrentHashMap<>() ;

    public static void main(String[] args) {

        System.out.println("[DİNLENİYOR] Sunucu " + PORT + " portunda başlatıldı...") ;

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {

            while (true) {

                Socket clientSocket = serverSocket.accept() ;
                System.out.println("[YENİ BAĞLANTI] " + clientSocket.getInetAddress() + " bağlandı.") ;

                // Virtual Threads
                Thread.startVirtualThread(() -> handleClient(clientSocket)) ;

            }

        }
        catch (IOException e) {

            e.printStackTrace() ;

        }

    }

    private static void handleClient(Socket socket) {

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

                        String username = (String) message.payload() ;
                        clients.put(username, out) ;
                        System.out.println("[KAYIT] Kullanıcı kaydedildi: " + username) ;

                        // Başarılı kayıttan sonra ACK gönder
                        out.writeObject(new Message(MessageType.ACK, "Kayıt başarılı.")) ;
                        out.flush() ;

                    }
                    case TEXT -> {

                        // TODO: Şifreli metin mesajını al ve alıcıya ilet

                    }
                    case KEY_EXCHANGE -> {

                        // TODO: Diffie-Hellman / RSA anahtar değişim mantığı

                    }
                    case FILE_START, FILE_CHUNK, FILE_END -> {

                        // TODO: Dosya transfer mantığı

                    }

                    default -> out.writeObject(new Message(MessageType.ERROR, "Bilinmeyen istek.")) ;

                }

            }

        }
        catch (Exception e) {

            System.out.println("[BAĞLANTI KESİLDİ] İstemci ayrıldı. Sebep: " + e.getMessage()) ;

        }

    }

}