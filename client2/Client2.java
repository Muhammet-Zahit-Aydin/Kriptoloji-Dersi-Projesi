package client2;

import common.Message;
import common.FileTransfer;
import common.FileTransferReceiver.ReceivedFile;
import common.FileTransferSender;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.io.Serial;
import java.nio.file.Path;
import java.util.ArrayList;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;

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
    private final JButton btnSelectPdf = new JButton("PDF Seç");
    private final JButton btnSendPdf = new JButton("PDF Gönder");
    private final JButton btnSavePdf = new JButton("Seçileni Kaydet");
    private final JLabel lblSendFile = new JLabel("PDF seçilmedi.");
    private final JLabel lblReceiveFile = new JLabel("Gelen PDF bekleniyor.");
    private final JProgressBar sendProgress = progressBar();
    private final JProgressBar receiveProgress = progressBar();
    private final DefaultComboBoxModel<ReceivedFile> receivedFiles = new DefaultComboBoxModel<>();
    private final JComboBox<ReceivedFile> cmbReceivedFiles = new JComboBox<>(receivedFiles);

    // Bu alanlara yalnızca Swing olay iş parçacığından (EDT) erişilir.
    private Client2Connection connection;
    private boolean connecting;
    private boolean sending;
    private boolean windowClosed;
    private Path selectedPdf;
    private boolean inspectingPdf;
    private boolean sendingFile;
    private boolean receivingFile;
    private boolean savingFile;

    public Client2() {
        setTitle("Client-2 (Hasan) - Güvensiz Metin / PDF");
        setSize(940, 760);
        setMinimumSize(new Dimension(820, 660));
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
        JPanel bottom = new JPanel(new BorderLayout(0, 10));
        bottom.add(composer, BorderLayout.NORTH);
        JPanel files = new JPanel(new java.awt.GridLayout(2, 1, 0, 8));
        files.add(filePanel("Giden PDF", lblSendFile, sendProgress, btnSelectPdf, btnSendPdf));
        JPanel incomingFile = filePanel("Gelen PDF", lblReceiveFile, receiveProgress, btnSavePdf);
        incomingFile.add(cmbReceivedFiles, BorderLayout.SOUTH);
        files.add(incomingFile);
        bottom.add(files, BorderLayout.CENTER);
        root.add(bottom, BorderLayout.SOUTH);

        btnConnect.addActionListener(e -> connectToServer());
        btnDisconnect.addActionListener(e -> disconnectFromServer());
        btnSend.addActionListener(e -> sendMessage());
        txtMessage.addActionListener(e -> sendMessage());
        btnSelectPdf.addActionListener(e -> selectPdf());
        btnSendPdf.addActionListener(e -> sendPdf());
        btnSavePdf.addActionListener(e -> savePdf());
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
                ArrayList<ReceivedFile> pending = new ArrayList<>();
                for (int i = 0; i < receivedFiles.getSize(); i++) pending.add(receivedFiles.getElementAt(i));
                // Kaydetme sürüyorsa pencerenin kapanmasını dosya kopyasıyla bekletme.
                Thread.ofPlatform().start(() -> pending.forEach(Client2::discard));
            }
        });

        setStatus("Bağlı değil", false);
        updateControls();
    }

    private static JProgressBar progressBar() {
        JProgressBar bar = new JProgressBar(0, 100);
        bar.setStringPainted(true);
        bar.setString("0 / 0 byte");
        return bar;
    }

    private static JPanel filePanel(String title, JLabel label, JProgressBar progress, JButton... buttons) {
        JPanel panel = new JPanel(new BorderLayout(6, 5));
        panel.setBorder(BorderFactory.createTitledBorder(title));
        panel.add(label, BorderLayout.NORTH);
        panel.add(progress, BorderLayout.CENTER);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        for (JButton button : buttons) actions.add(button);
        panel.add(actions, BorderLayout.EAST);
        return panel;
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
        setStatus("Bağlanıyor...", false);
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
                    append(txtIncoming, "[Sunucu] Güvensiz metin bağlantısı kuruldu.");
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
        markInterruptedFiles();
        if (previous != null) {
            previous.close();
            append(txtIncoming, "[Sistem] Bağlantı kesildi.");
        }
        setStatus("Bağlı değil", false);
        updateControls();
    }

    private void sendMessage() {
        if (connection == null || sending || sendingFile || txtMessage.getText().isBlank()) {
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
                SwingUtilities.invokeLater(() -> {
                    if (connection == current) {
                        sending = false;
                        append(txtIncoming, "[Hata] " + e.getMessage());
                        updateControls(); // Yerel boyut hatasında bağlantı hâlâ açık olabilir.
                    }
                });
            }
        });
    }

    private void selectPdf() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new FileNameExtensionFilter("PDF dosyaları (*.pdf)", "pdf"));
        chooser.setAcceptAllFileFilterUsed(false);
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        Path path = chooser.getSelectedFile().toPath();
        inspectingPdf = true;
        updateControls();
        Thread.startVirtualThread(() -> {
            try {
                FileTransfer.Start metadata = FileTransferSender.inspect(path);
                SwingUtilities.invokeLater(() -> {
                    inspectingPdf = false;
                    selectedPdf = path;
                    lblSendFile.setText(metadata.fileName() + " — " + metadata.size() + " byte");
                    lblSendFile.setToolTipText(path.toString());
                    showProgress(sendProgress, 0, metadata.size());
                    updateControls();
                });
            } catch (IOException e) {
                SwingUtilities.invokeLater(() -> {
                    inspectingPdf = false;
                    append(txtIncoming, "[PDF / Hata] " + e.getMessage());
                    updateControls();
                });
            }
        });
    }

    private void sendPdf() {
        if (connection == null || selectedPdf == null || sendingFile || sending || inspectingPdf) return;
        Client2Connection current = connection;
        Path path = selectedPdf;
        sendingFile = true;
        updateControls();
        Thread.startVirtualThread(() -> {
            int[] lastPercent = {-1};
            try {
                current.sendPdf(path, (file, bytes) -> {
                    int percent = percent(bytes, file.size());
                    if (percent == lastPercent[0]) return;
                    lastPercent[0] = percent;
                    SwingUtilities.invokeLater(() -> {
                        if (connection == current) {
                            lblSendFile.setText(file.fileName() + " — " + file.size() + " byte — Gönderiliyor");
                            showProgress(sendProgress, bytes, file.size());
                        }
                    });
                });
                SwingUtilities.invokeLater(() -> {
                    if (connection == current) {
                        sendingFile = false;
                        lblSendFile.setText(path.getFileName() + " — Sunucuya yazıldı (teslim onayı yok)");
                        append(txtOutgoing, "[PDF] " + path.getFileName() + " sunucuya yazıldı.");
                        updateControls();
                    }
                });
            } catch (IOException e) {
                SwingUtilities.invokeLater(() -> {
                    if (connection == current) {
                        sendingFile = false;
                        lblSendFile.setText(path.getFileName() + " — Gönderim başarısız");
                        append(txtIncoming, "[PDF / Hata] " + e.getMessage());
                        updateControls();
                    }
                });
            }
        });
    }

    private void savePdf() {
        ReceivedFile file = (ReceivedFile) receivedFiles.getSelectedItem();
        if (file == null || savingFile) return;
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File(file.metadata().fileName()));
        chooser.setFileFilter(new FileNameExtensionFilter("PDF dosyaları (*.pdf)", "pdf"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        Path destination = chooser.getSelectedFile().toPath();
        savingFile = true;
        updateControls();
        Thread.startVirtualThread(() -> {
            try {
                file.saveTo(destination);
                discard(file);
                SwingUtilities.invokeLater(() -> {
                    savingFile = false;
                    receivedFiles.removeElement(file);
                    append(txtIncoming, "[PDF] Kaydedildi: " + destination);
                    updateControls();
                });
            } catch (IOException e) {
                SwingUtilities.invokeLater(() -> {
                    savingFile = false;
                    append(txtIncoming, "[PDF / Hata] Kaydedilemedi: " + e.getMessage()
                            + ". Hedef varsa farklı bir ad seçin.");
                    updateControls(); // İptal veya hatada alınan dosya tekrar kaydedilebilir.
                });
            }
        });
    }

    private void markInterruptedFiles() {
        if (sendingFile) lblSendFile.setText("PDF gönderimi yarıda kesildi.");
        if (receivingFile) lblReceiveFile.setText("PDF alımı yarıda kesildi; tamamlanmış sayılmadı.");
        sendingFile = false;
        receivingFile = false;
    }

    private static int percent(long bytes, long size) { return (int) (bytes * 100 / size); }

    private static void showProgress(JProgressBar bar, long bytes, long size) {
        bar.setValue(percent(bytes, size));
        bar.setString(bytes + " / " + size + " byte");
    }

    private static void discard(ReceivedFile file) {
        try { file.close(); } catch (IOException ignored) { }
    }

    private final class SessionListener implements Client2Connection.Listener {
        private Client2Connection session;
        private int lastPercent = -1;
        private java.util.UUID incomingFileId;

        @Override
        public void onFileProgress(FileTransfer.Start file, long bytes) {
            int progress = percent(bytes, file.size());
            if (file.fileId().equals(incomingFileId) && progress == lastPercent) return;
            incomingFileId = file.fileId();
            lastPercent = progress;
            SwingUtilities.invokeLater(() -> {
                if (connection != session || windowClosed) return;
                receivingFile = true;
                lblReceiveFile.setText(file.fileName() + " — " + file.size() + " byte — "
                        + (bytes == file.size() ? "Bitiş mesajı bekleniyor" : "Alınıyor"));
                showProgress(receiveProgress, bytes, file.size());
            });
        }

        @Override
        public void onFileReceived(ReceivedFile file) {
            SwingUtilities.invokeLater(() -> {
                if (connection != session || windowClosed) {
                    Thread.startVirtualThread(() -> discard(file));
                    return;
                }
                receivingFile = false;
                receivedFiles.addElement(file);
                receivedFiles.setSelectedItem(file);
                lblReceiveFile.setText(file.metadata().fileName() + " — " + file.metadata().size()
                        + " byte — Alındı, kaydedilmeyi bekliyor");
                showProgress(receiveProgress, file.metadata().size(), file.metadata().size());
                append(txtIncoming, "[PDF] Alındı: " + file.metadata().fileName());
                updateControls();
            });
        }

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
                    markInterruptedFiles();
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
        txtMessage.setEnabled(connected && !sending && !sendingFile);
        btnSend.setEnabled(connected && !sending && !sendingFile && !txtMessage.getText().isBlank());
        btnSelectPdf.setEnabled(!sendingFile && !inspectingPdf);
        btnSendPdf.setEnabled(connected && selectedPdf != null && !sending && !sendingFile && !inspectingPdf);
        btnSavePdf.setEnabled(receivedFiles.getSize() > 0 && !savingFile);
        cmbReceivedFiles.setEnabled(receivedFiles.getSize() > 0 && !savingFile);
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
