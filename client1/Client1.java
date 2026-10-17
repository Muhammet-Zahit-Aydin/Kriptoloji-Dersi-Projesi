package client1;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.Socket;

public class Client1 extends JFrame {
    // Arayüz Bileşenleri
    private JTextField txtIp;
    private JTextField txtPort;
    private JButton btnConnect;
    private JButton btnDisconnect;
    private JTextArea txtMessages;
    private JTextField txtMessageInput;
    private JButton btnSend;
    private JButton btnFileSelect;

    // Ağ Bileşenleri
    private Socket socket;
    private ObjectOutputStream out;
    private ObjectInputStream in;

    public Client1() {
        // Ana Pencere Ayarları
        setTitle("Client-1 (Hüseyin)");
        setSize(600, 450);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout(10, 10));

        // 1. Üst Panel: Sunucu IP/Port ve Bağlantı Butonları
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.add(new JLabel("Sunucu IP:"));
        txtIp = new JTextField("127.0.0.1", 10);
        topPanel.add(txtIp);
        
        topPanel.add(new JLabel("Port:"));
        txtPort = new JTextField("5000", 5);
        topPanel.add(txtPort);
        
        btnConnect = new JButton("Bağlan");
        btnDisconnect = new JButton("Bağlantıyı Kes");
        btnDisconnect.setEnabled(false); // Başlangıçta pasif
        
        topPanel.add(btnConnect);
        topPanel.add(btnDisconnect);
        add(topPanel, BorderLayout.NORTH);

        // 2. Orta Panel: Mesaj Görüntüleme Alanı
        txtMessages = new JTextArea();
        txtMessages.setEditable(false);
        txtMessages.setLineWrap(true);
        JScrollPane scrollPane = new JScrollPane(txtMessages);
        add(scrollPane, BorderLayout.CENTER);

        // 3. Alt Panel: Dosya Seçimi, Mesaj Yazma ve Gönderme
        JPanel bottomPanel = new JPanel(new BorderLayout(5, 5));
        
        btnFileSelect = new JButton("Dosya Seç");
        bottomPanel.add(btnFileSelect, BorderLayout.WEST);
        
        txtMessageInput = new JTextField();
        bottomPanel.add(txtMessageInput, BorderLayout.CENTER);
        
        btnSend = new JButton("Gönder");
        btnSend.setEnabled(false); // Başlangıçta pasif
        bottomPanel.add(btnSend, BorderLayout.EAST);
        
        add(bottomPanel, BorderLayout.SOUTH);

        // Olay Dinleyicileri (Event Listeners)
        btnConnect.addActionListener(e -> connectToServer());
        btnDisconnect.addActionListener(e -> disconnectFromServer());
        btnFileSelect.addActionListener(e -> selectFile());
    }

    // Sunucuya Bağlanma Fonksiyonu
    private void connectToServer() {
        String ip = txtIp.getText().trim();
        int port;

        try {
            port = Integer.parseInt(txtPort.getText().trim());
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "Geçersiz Port Numarası!", "Hata", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Arayüzün donmaması için bağlantı işlemini ayrı bir thread'de yapıyoruz
        new Thread(() -> {
            try {
                socket = new Socket(ip, port);
                // Proje yapısındaki common/Message.java ile uyumlu olması için Object streams kullanıldı
                out = new ObjectOutputStream(socket.getOutputStream());
                in = new ObjectInputStream(socket.getInputStream());

                SwingUtilities.invokeLater(() -> {
                    txtMessages.append("Sunucuya bağlandı: " + ip + ":" + port + "\n");
                    btnConnect.setEnabled(false);
                    txtIp.setEditable(false);
                    txtPort.setEditable(false);
                    btnDisconnect.setEnabled(true);
                    btnSend.setEnabled(true);
                });

            } catch (IOException ex) {
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(this, "Bağlantı hatası: " + ex.getMessage(), "Hata", JOptionPane.ERROR_MESSAGE);
                });
            }
        }).start();
    }

    // Sunucudan Bağlantıyı Kesme Fonksiyonu
    private void disconnectFromServer() {
        try {
            if (out != null) out.close();
            if (in != null) in.close();
            if (socket != null && !socket.isClosed()) socket.close();

            txtMessages.append("Bağlantı kesildi.\n");
            
            // Arayüzü başlangıç durumuna döndür
            btnConnect.setEnabled(true);
            txtIp.setEditable(true);
            txtPort.setEditable(true);
            btnDisconnect.setEnabled(false);
            btnSend.setEnabled(false);

        } catch (IOException ex) {
            txtMessages.append("Bağlantı kesilirken hata oluştu: " + ex.getMessage() + "\n");
        }
    }

    // Dosya Seçme Fonksiyonu
    private void selectFile() {
        JFileChooser fileChooser = new JFileChooser();
        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            txtMessages.append("Sistem mesajı - Dosya seçildi: " + selectedFile.getName() + "\n");
            // Gelecek günlerde eklenecek dosya gönderme mantığı buraya entegre edilecek
        }
    }

    public static void main(String[] args) {
        // Swing arayüzünü güvenli bir şekilde başlat
        SwingUtilities.invokeLater(() -> {
            Client1 frame = new Client1();
            frame.setVisible(true);
        });
    }
}