package client2;

import common.Message;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.io.Serial;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

public class Client2 extends JFrame {
    @Serial
    private static final long serialVersionUID = 1L;
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final JTextField txtIp = new JTextField("127.0.0.1", 12);
    private final JTextField txtPort = new JTextField("5000", 5);
    private final JButton btnConnect = new JButton("Bağlan");
    private final JButton btnDisconnect = new JButton("Bağlantıyı Kes");
    private final JLabel lblStatus = new JLabel();
    private final JTextArea txtIncoming = messageArea();
    private final JTextArea txtOutgoing = messageArea();
    private final JTextField txtMessage = new JTextField();
    private final JButton btnSend = new JButton("Gönder");

    // Bu alanlara yalnızca Swing olay iş parçacığından (EDT) erişilir.
    private Client2Connection connection;
    private boolean connecting;
    private boolean sending;
    private boolean windowClosed;

    public Client2() {
        setTitle("Client-2 (Hasan) - Güvensiz Metin");
        setSize(860, 540);
        setMinimumSize(new Dimension(760, 440));
        setLocationRelativeTo(null);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);

        JPanel root = new JPanel(new BorderLayout(10, 10));
        root.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        setContentPane(root);

        JPanel connectionPanel = new JPanel(new BorderLayout());
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        controls.add(new JLabel("Sunucu IP:"));
        controls.add(txtIp);
        controls.add(new JLabel("Port:"));
        controls.add(txtPort);
        controls.add(btnConnect);
        controls.add(btnDisconnect);
        connectionPanel.add(controls, BorderLayout.NORTH);

        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 10));
        statusPanel.add(new JLabel("İstemci: " + Client2Connection.CLIENT_ID + "  |  Durum:"));
        statusPanel.add(lblStatus);
        connectionPanel.add(statusPanel, BorderLayout.SOUTH);
        root.add(connectionPanel, BorderLayout.NORTH);

        JSplitPane messages = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                messagePanel("Gelen mesajlar / Sunucu bildirimleri", txtIncoming),
                messagePanel("Giden mesajlar (sunucuya yazılan)", txtOutgoing));
        messages.setResizeWeight(0.5);
        messages.setBorder(null);
        root.add(messages, BorderLayout.CENTER);

        JPanel composer = new JPanel(new BorderLayout(8, 0));
        composer.setBorder(BorderFactory.createTitledBorder("Metin mesajı"));
        composer.add(txtMessage, BorderLayout.CENTER);
        composer.add(btnSend, BorderLayout.EAST);
        root.add(composer, BorderLayout.SOUTH);

        btnConnect.addActionListener(e -> connectToServer());
        btnDisconnect.addActionListener(e -> disconnectFromServer());
        btnSend.addActionListener(e -> sendMessage());
        txtMessage.addActionListener(e -> sendMessage());
        txtMessage.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { updateControls(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { updateControls(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updateControls(); }
        });
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosed(WindowEvent e) {
                windowClosed = true;
                disconnectFromServer();
            }
        });

        setStatus("Bağlı değil", false);
        updateControls();
    }

    private static JTextArea messageArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        return area;
    }

    private static JPanel messagePanel(String title, JTextArea area) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(title));
        panel.add(new JScrollPane(area), BorderLayout.CENTER);
        return panel;
    }

    private void connectToServer() {
        if (connecting || connection != null || windowClosed) {
            return;
        }
        String host = txtIp.getText().trim();
        int port;
        try {
            port = Integer.parseInt(txtPort.getText().trim());
            if (host.isEmpty() || port < 1 || port > 65535) {
                throw new IllegalArgumentException();
            }
        } catch (IllegalArgumentException e) {
            JOptionPane.showMessageDialog(this,
                    "Sunucu IP/adresini ve 1-65535 arasında bir port girin.",
                    "Geçersiz bağlantı bilgisi", JOptionPane.ERROR_MESSAGE);
            return;
        }

        connecting = true;
        setStatus("Bağlanıyor / Kayıt bekleniyor...", false);
        updateControls();
        // Her bağlantıya ayrı dinleyici: eski bağlantının bekleyen bildirimi yenisini etkilemez.
        SessionListener listener = new SessionListener();
        Thread.startVirtualThread(() -> {
            try {
                Client2Connection opened = Client2Connection.connect(host, port, listener);
                SwingUtilities.invokeLater(() -> {
                    connecting = false;
                    if (windowClosed) {
                        opened.close();
                        return;
                    }
                    connection = opened;
                    listener.session = opened;
                    setStatus("Bağlı - " + host + ":" + port, true);
                    append(txtIncoming, "[Sunucu] Client2 kaydı onaylandı.");
                    updateControls();
                    opened.startReceiving();
                    txtMessage.requestFocusInWindow();
                });
            } catch (IOException | RuntimeException e) {
                SwingUtilities.invokeLater(() -> {
                    connecting = false;
                    if (!windowClosed) {
                        setStatus("Bağlantı kurulamadı", false);
                        append(txtIncoming, "[Hata] " + e.getMessage());
                        updateControls();
                    }
                });
            }
        });
    }

    private void disconnectFromServer() {
        Client2Connection previous = connection;
        connection = null;
        sending = false;
        if (previous != null) {
            previous.close();
            append(txtIncoming, "[Sistem] Bağlantı kesildi.");
        }
        setStatus("Bağlı değil", false);
        updateControls();
    }

    private void sendMessage() {
        if (connection == null || sending || txtMessage.getText().isBlank()) {
            return;
        }
        Client2Connection current = connection;
        String text = txtMessage.getText();
        sending = true;
        updateControls();
        Thread.startVirtualThread(() -> {
            try {
                current.sendText(text);
                SwingUtilities.invokeLater(() -> {
                    // Sokete yazmak, alıcının mesajı teslim aldığı anlamına gelmez.
                    append(txtOutgoing, "Client2 → Sunucu: " + text);
                    if (connection == current) {
                        sending = false;
                        txtMessage.setText("");
                        updateControls();
                        txtMessage.requestFocusInWindow();
                    }
                });
            } catch (IOException e) {
                // Bağlantı dinleyicisi hatayı gösterir; gönderilmemiş metin korunur.
            }
        });
    }

    private final class SessionListener implements Client2Connection.Listener {
        private Client2Connection session;

        @Override
        public void onMessage(Message message) {
            SwingUtilities.invokeLater(() -> {
                if (connection != session || windowClosed) {
                    return;
                }
                switch (message.type()) {
                    case TEXT -> append(txtIncoming, "[Gelen] " + message.payload());
                    case ACK -> append(txtIncoming, "[Sunucu / ACK] " + message.payload());
                    case ERROR -> append(txtIncoming, "[Sunucu / Hata] " + message.payload());
                    default -> append(txtIncoming, "[Sunucu] Henüz desteklenmeyen mesaj: " + message.type());
                }
            });
        }

        @Override
        public void onDisconnected(String reason) {
            SwingUtilities.invokeLater(() -> {
                if (connection == session && !windowClosed) {
                    connection = null;
                    sending = false;
                    setStatus("Bağlı değil", false);
                    append(txtIncoming, "[Sistem] " + reason);
                    updateControls();
                }
            });
        }
    }

    private void updateControls() {
        boolean connected = connection != null;
        btnConnect.setEnabled(!connecting && !connected);
        btnDisconnect.setEnabled(connected);
        txtIp.setEditable(!connecting && !connected);
        txtPort.setEditable(!connecting && !connected);
        txtMessage.setEnabled(connected && !sending);
        btnSend.setEnabled(connected && !sending && !txtMessage.getText().isBlank());
    }

    private void setStatus(String text, boolean connected) {
        lblStatus.setText(text);
        lblStatus.setForeground(connected ? new Color(0, 115, 45) : Color.DARK_GRAY);
    }

    private static void append(JTextArea area, String text) {
        area.append("[" + LocalTime.now().format(TIME_FORMAT) + "] " + text + "\n");
        area.setCaretPosition(area.getDocument().getLength());
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new Client2().setVisible(true));
    }
}
