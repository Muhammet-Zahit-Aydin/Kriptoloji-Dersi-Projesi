package client1;

import common.FileTransfer;
import common.FileTransferReceiver;
import common.FileTransferSender;
import common.Message;
import common.MessageType;
import common.SecureFrameCodec;
import common.crypto.CryptoMode;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.UTFDataFormatException;
import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.file.Path;

public class Client1 extends JFrame {
    private final JTextField txtIp = new JTextField("127.0.0.1", 10);
    private final JTextField txtPort = new JTextField("5000", 5);
    private final JComboBox<CryptoMode> cmbCryptoMode = new JComboBox<>(CryptoMode.values());
    private final JPasswordField txtPassphrase = new JPasswordField(12);
    private final JButton btnConnect = new JButton("Bağlan");
    private final JButton btnDisconnect = new JButton("Bağlantıyı Kes");
    private final JTextArea txtMessages = new JTextArea();
    private final JTextField txtMessageInput = new JTextField();
    private final JButton btnSend = new JButton("Gönder");
    private final JButton btnFileSelect = new JButton("PDF Gönder");
    private final JButton btnSavePdf = new JButton("Gelen PDF'yi Kaydet");
    private final JLabel lblStatus = new JLabel("Bağlı değil");
    private final FileTransferReceiver fileReceiver = new FileTransferReceiver();

    private volatile Socket socket;
    private volatile ObjectOutputStream out;
    private volatile ObjectInputStream in;
    private volatile boolean connected;
    private volatile boolean connecting;
    private volatile boolean closing;
    private volatile boolean sendingFile;
    private volatile FileTransferReceiver.ReceivedFile receivedFile;
    private CryptoMode activeMode = CryptoMode.INSECURE;
    private String activePassword;

    public Client1() {
        setTitle("Client-1 (Hüseyin) - Metin / PDF / AES");
        setSize(760, 560);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout(8, 8));

        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        JPanel connectionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
        connectionRow.add(new JLabel("Sunucu IP:")); connectionRow.add(txtIp);
        connectionRow.add(new JLabel("Port:")); connectionRow.add(txtPort);
        connectionRow.add(btnConnect); connectionRow.add(btnDisconnect);
        JPanel securityRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
        securityRow.add(new JLabel("Şifreleme:")); securityRow.add(cmbCryptoMode);
        securityRow.add(new JLabel("Ortak parola:")); securityRow.add(txtPassphrase);
        top.add(connectionRow); top.add(securityRow);
        add(top, BorderLayout.NORTH);

        txtMessages.setEditable(false); txtMessages.setLineWrap(true); txtMessages.setWrapStyleWord(true);
        add(new JScrollPane(txtMessages), BorderLayout.CENTER);
        JPanel compose = new JPanel(new BorderLayout(6, 6));
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        actions.add(btnFileSelect); actions.add(btnSavePdf); actions.add(btnSend);
        compose.add(txtMessageInput, BorderLayout.CENTER); compose.add(actions, BorderLayout.EAST);
        JPanel bottom = new JPanel(new BorderLayout()); bottom.add(lblStatus, BorderLayout.NORTH); bottom.add(compose, BorderLayout.SOUTH);
        add(bottom, BorderLayout.SOUTH);

        btnConnect.addActionListener(e -> connectToServer());
        btnDisconnect.addActionListener(e -> disconnectFromServer());
        btnSend.addActionListener(e -> sendMessage());
        txtMessageInput.addActionListener(e -> sendMessage());
        btnFileSelect.addActionListener(e -> sendPdf());
        btnSavePdf.addActionListener(e -> savePdf());
        addWindowListener(new WindowAdapter() { @Override public void windowClosed(WindowEvent e) { closeAll(); } });
        updateControls();
    }

    private void connectToServer() {
        if (connected || connecting || closing) return;
        String host=txtIp.getText().trim(); int port;
        try { port=Integer.parseInt(txtPort.getText().trim()); if(host.isBlank()||port<1||port>65535) throw new IllegalArgumentException(); }
        catch(IllegalArgumentException e) { JOptionPane.showMessageDialog(this,"Sunucu adresi ve 1-65535 arasında port girin.","Bağlantı bilgisi",JOptionPane.ERROR_MESSAGE); return; }
        CryptoMode mode=(CryptoMode)cmbCryptoMode.getSelectedItem();
        String password=new String(txtPassphrase.getPassword());
        if(mode!=CryptoMode.INSECURE&&password.isBlank()) { JOptionPane.showMessageDialog(this,"Şifreli modda Client-2 ile aynı parolayı kullanın.","Parola gerekli",JOptionPane.ERROR_MESSAGE); return; }
        connecting=true; lblStatus.setText("Bağlanıyor..."); updateControls();
        Thread.startVirtualThread(() -> {
            try {
                Socket openedSocket=new Socket(host,port);
                ObjectOutputStream openedOut=new ObjectOutputStream(openedSocket.getOutputStream()); openedOut.flush();
                ObjectInputStream openedIn=new ObjectInputStream(openedSocket.getInputStream());
                SwingUtilities.invokeLater(() -> {
                    if(closing) { connecting=false; try { openedSocket.close(); } catch(IOException ignored) { } return; }
                    connecting=false; socket=openedSocket; out=openedOut; in=openedIn; activeMode=mode; activePassword=password; connected=true;
                    lblStatus.setText("Bağlı — "+mode); append("[Sistem] Sunucuya bağlandı: "+host+":"+port);
                    updateControls(); Thread.startVirtualThread(this::receiveMessages);
                });
            } catch(IOException e) {
                SwingUtilities.invokeLater(() -> { connecting=false; lblStatus.setText("Bağlantı kurulamadı"); append("[Hata] "+e.getMessage()); updateControls(); });
            }
        });
    }

    private void disconnectFromServer() {
        connected=false; Socket current=socket; socket=null;
        if(current!=null) try { current.close(); } catch(IOException ignored) { }
        try { fileReceiver.close(); } catch(IOException ignored) { }
        lblStatus.setText("Bağlı değil"); append("[Sistem] Bağlantı kesildi."); updateControls();
    }

    private void sendMessage() {
        String text=txtMessageInput.getText(); if(!connected||text.isBlank()) return;
        String frame;
        try { frame=SecureFrameCodec.encode(new Message(MessageType.TEXT,"Client1","Client2",text,null),activeMode,activePassword); }
        catch(RuntimeException e) { append("[Hata] "+e.getMessage()); return; }
        try {
            writeFrame(frame); append("Ben: "+text); txtMessageInput.setText("");
        } catch(UTFDataFormatException e) { append("[Hata] Mesaj seçilen şifreleme kipinde taşıma sınırını aşıyor.");
        } catch(IOException e) { append("[Gönderim hatası] "+e.getMessage()); disconnectFromServer(); }
    }

    private void writeFrame(String frame) throws IOException {
        try(DataOutputStream check=new DataOutputStream(new ByteArrayOutputStream())) { check.writeUTF(frame); }
        ObjectOutputStream current=out;
        if(!connected||current==null) throw new IOException("Sunucu bağlantısı kapalı.");
        synchronized(current) { current.writeUTF(frame); current.flush(); }
    }

    private void receiveMessages() {
        try {
            while(connected) {
                String frame=in.readUTF(); Message message=SecureFrameCodec.decode(frame,activePassword);
                if(message.type()==MessageType.TEXT) SwingUtilities.invokeLater(() -> append("Karşı Taraf: "+message.payload()));
                else receiveFile(message);
            }
        } catch(EOFException e) { if(connected) SwingUtilities.invokeLater(() -> append("[Sistem] Sunucu bağlantıyı kapattı.")); }
        catch(IOException|RuntimeException e) { if(connected) SwingUtilities.invokeLater(() -> append("[Alım hatası] "+e.getMessage())); }
        finally { if(connected) SwingUtilities.invokeLater(this::disconnectFromServer); }
    }

    private void receiveFile(Message message) throws IOException {
        synchronized(fileReceiver) {
            switch(message.type()) {
                case FILE_START -> { fileReceiver.start((FileTransfer.Start)message.payload()); SwingUtilities.invokeLater(() -> append("[PDF] Alınıyor: "+((FileTransfer.Start)message.payload()).fileName())); }
                case FILE_CHUNK -> fileReceiver.append((FileTransfer.Chunk)message.payload());
                case FILE_END -> {
                    FileTransferReceiver.ReceivedFile complete=fileReceiver.finish((FileTransfer.End)message.payload());
                    FileTransferReceiver.ReceivedFile previous=receivedFile; receivedFile=complete;
                    if(previous!=null) try { previous.close(); } catch(IOException ignored) { }
                    SwingUtilities.invokeLater(() -> { append("[PDF] Alındı: "+complete.metadata().fileName()+" ("+complete.metadata().size()+" byte)"); updateControls(); });
                }
                default -> throw new IOException("Desteklenmeyen paket: "+message.type());
            }
        }
    }

    private void sendPdf() {
        if(!connected||sendingFile) return;
        JFileChooser chooser=new JFileChooser(); chooser.setFileFilter(new FileNameExtensionFilter("PDF dosyaları (*.pdf)","pdf")); chooser.setAcceptAllFileFilterUsed(false);
        if(chooser.showOpenDialog(this)!=JFileChooser.APPROVE_OPTION) return;
        Path path=chooser.getSelectedFile().toPath(); sendingFile=true; updateControls();
        Thread.startVirtualThread(() -> {
            try {
                FileTransfer.Start metadata=FileTransferSender.inspect(path);
                FileTransferSender.send(path,metadata,"Client1","Client2",packet -> writeFrame(SecureFrameCodec.encode(packet)),bytes -> {
                    if(bytes==metadata.size()||bytes==0) SwingUtilities.invokeLater(() -> append("[PDF] "+metadata.fileName()+": "+bytes+" / "+metadata.size()+" byte"));
                });
                SwingUtilities.invokeLater(() -> append("[PDF] Gönderildi: "+metadata.fileName()));
            } catch(IOException|RuntimeException e) { SwingUtilities.invokeLater(() -> append("[PDF / Hata] "+e.getMessage())); }
            finally { sendingFile=false; SwingUtilities.invokeLater(this::updateControls); }
        });
    }

    private void savePdf() {
        FileTransferReceiver.ReceivedFile file=receivedFile; if(file==null) return;
        JFileChooser chooser=new JFileChooser(); chooser.setSelectedFile(new java.io.File(file.metadata().fileName()));
        chooser.setFileFilter(new FileNameExtensionFilter("PDF dosyaları (*.pdf)","pdf"));
        if(chooser.showSaveDialog(this)!=JFileChooser.APPROVE_OPTION) return;
        Path destination=chooser.getSelectedFile().toPath();
        Thread.startVirtualThread(() -> {
            try { file.saveTo(destination); if(receivedFile==file) receivedFile=null; file.close(); SwingUtilities.invokeLater(() -> { append("[PDF] Kaydedildi: "+destination); updateControls(); }); }
            catch(IOException e) { SwingUtilities.invokeLater(() -> append("[PDF / Hata] "+e.getMessage()+"; başka bir dosya adı seçin.")); }
        });
    }

    private void updateControls() {
        btnConnect.setEnabled(!connected&&!connecting); btnDisconnect.setEnabled(connected);
        txtIp.setEditable(!connected&&!connecting); txtPort.setEditable(!connected&&!connecting); cmbCryptoMode.setEnabled(!connected&&!connecting); txtPassphrase.setEditable(!connected&&!connecting);
        btnSend.setEnabled(connected); txtMessageInput.setEnabled(connected); btnFileSelect.setEnabled(connected&&!sendingFile);
        btnSavePdf.setEnabled(receivedFile!=null);
    }

    private void append(String text) { txtMessages.append(text+"\n"); txtMessages.setCaretPosition(txtMessages.getDocument().getLength()); }

    private void closeAll() {
        closing=true; connected=false; Socket current=socket; socket=null;
        if(current!=null) try { current.close(); } catch(IOException ignored) { }
        try { fileReceiver.close(); } catch(IOException ignored) { }
        FileTransferReceiver.ReceivedFile complete=receivedFile; receivedFile=null;
        if(complete!=null) try { complete.close(); } catch(IOException ignored) { }
    }

    public static void main(String[] args) { SwingUtilities.invokeLater(() -> new Client1().setVisible(true)); }
}
