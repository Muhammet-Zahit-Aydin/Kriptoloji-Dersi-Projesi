package server;

import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ConcurrentHashMap;

public class Server {

    private static final int PORT = 5000;

    // Şifresiz test aşaması: Sadece bağlı istemcilerin soketlerini ve çıktı akışlarını tutuyoruz
    private static final ConcurrentHashMap<Socket, ObjectOutputStream> clients = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        System.out.println("[DİNLENİYOR] Sunucu " + PORT + " portunda başlatıldı (Güvensiz Metin Test Modu)...");

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("[YENİ BAĞLANTI] " + clientSocket.getInetAddress() + " bağlandı.");

                // Virtual Threads - Her istemciyi ayrı bir iş parçacığında dinle
                Thread.startVirtualThread(() -> handleClient(clientSocket));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket socket) {
        try {
            // İletişim akışlarını oluştur
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            // İstemciyi aktif listeye ekle
            clients.put(socket, out);

            while (true) {
                // readUTF: İstemciden gelen UTF-8 mesajı ve framing (boyut) bilgisini okur
                String incomingMessage = in.readUTF();
                System.out.println("[" + socket.getInetAddress() + "] Gelen Mesaj: " + incomingMessage);

                // Gelen mesajı, gönderen hariç diğer tüm istemcilere dağıt
                broadcastMessage(incomingMessage, socket);
            }

        } catch (EOFException e) {
            System.out.println("[KOPTU] İstemci bağlantıyı güvenli şekilde kapattı: " + socket.getInetAddress());
        } catch (Exception e) {
            System.out.println("[HATA] İstemci bağlantı hatası: " + e.getMessage());
        } finally {
            // Bağlantı koptuğunda istemciyi listeden sil ve soketi kapat
            clients.remove(socket);
            System.out.println("[SİLİNDİ] " + socket.getInetAddress() + " sistemden kaldırıldı.");
            try {
                if (!socket.isClosed()) socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    // Mesajı diğer istemcilere iletme (Yönlendirme) metodu
    private static void broadcastMessage(String message, Socket senderSocket) {
        for (ConcurrentHashMap.Entry<Socket, ObjectOutputStream> entry : clients.entrySet()) {
            Socket targetSocket = entry.getKey();
            ObjectOutputStream targetOut = entry.getValue();

            // Mesajı gönderenin kendisine geri yollama (sadece hedefe gönder)
            if (targetSocket != senderSocket) {
                try {
                    targetOut.writeUTF(message);
                    targetOut.flush();
                } catch (IOException e) {
                    System.out.println("[İLETİM HATASI] Hedefe ulaşılamadı: " + targetSocket.getInetAddress());
                }
            }
        }
    }
}