package common;

import common.crypto.AesGcmCryptoService;
import common.crypto.CryptoMode;
import common.crypto.CryptoService;
import common.crypto.ManualAes128CbcCryptoService;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/** UTF transport codec for plain text, PDF packets, and password-protected text. */
public final class SecureFrameCodec {
    private static final String PREFIX = "\u001eKRIPTO1:";
    private static final int SALT_BYTES = 16;
    private static final int HMAC_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final CryptoService GCM = new AesGcmCryptoService();
    private static final CryptoService MANUAL_CBC = new ManualAes128CbcCryptoService();
    private SecureFrameCodec() { }

    public static String encode(Message message) { return encode(message, CryptoMode.INSECURE, null); }

    public static String encode(Message message, CryptoMode mode, String password) {
        if (message == null || message.type() == null) throw new IllegalArgumentException("Mesaj gerekli.");
        CryptoMode selected = mode == null ? CryptoMode.INSECURE : mode;
        if (message.type() == MessageType.TEXT && selected != CryptoMode.INSECURE)
            return encodeProtectedText((String) message.payload(), message.senderId(), message.targetId(), selected, password);
        if (message.type() == MessageType.TEXT) {
            if (!(message.payload() instanceof String text)) throw new IllegalArgumentException("Metin mesajı String olmalı.");
            if (!text.startsWith(PREFIX)) return text;
            return encodeBinary((byte)4, message, out -> out.writeUTF(text));
        }
        return switch (message.type()) {
            case FILE_START -> encodeBinary((byte)1, message, out -> {
                FileTransfer.Start start = (FileTransfer.Start) message.payload();
                writeUuid(out,start.fileId()); out.writeUTF(start.fileName()); out.writeLong(start.size());
            });
            case FILE_CHUNK -> encodeBinary((byte)2, message, out -> {
                FileTransfer.Chunk chunk = (FileTransfer.Chunk) message.payload();
                writeUuid(out,chunk.fileId()); out.writeInt(chunk.sequence()); byte[] data=chunk.data(); out.writeInt(data.length); out.write(data);
            });
            case FILE_END -> encodeBinary((byte)3, message, out -> {
                FileTransfer.End end = (FileTransfer.End) message.payload(); writeUuid(out,end.fileId()); out.writeInt(end.chunkCount());
            });
            default -> throw new IllegalArgumentException("Desteklenmeyen mesaj türü: " + message.type());
        };
    }

    public static String encodeProtectedText(String text, String sender, String target, CryptoMode mode, String password) {
        if (text == null) throw new IllegalArgumentException("Metin gerekli.");
        if (mode == null || mode == CryptoMode.INSECURE) return encode(new Message(MessageType.TEXT,sender,target,text,null));
        if (password == null || password.isBlank()) throw new IllegalArgumentException("Şifreli mod için iki istemcide aynı parolayı girin.");
        try {
            byte kind = mode == CryptoMode.AES_128_GCM ? (byte)5 : (byte)6;
            byte[] salt = new byte[SALT_BYTES]; RANDOM.nextBytes(salt);
            CryptoService service = service(mode);
            byte[] key = service.deriveKey(password, salt);
            byte[] plain = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] encrypted = mode==CryptoMode.AES_128_GCM
                    ? ((AesGcmCryptoService)GCM).encrypt(plain,key,associatedData(kind,sender,target,salt))
                    : service.encrypt(plain,key);
            byte[] body = encryptedBody(kind, sender, target, salt, encrypted);
            if (mode == CryptoMode.AES_128_CBC_MANUAL) {
                byte[] macKey = service.deriveKey(password + "::frame-mac", salt);
                byte[] mac = hmac(body, macKey);
                body = concat(body, mac);
            }
            return PREFIX + Base64.getEncoder().encodeToString(body);
        } catch (Exception e) { throw new IllegalArgumentException("Şifreli metin kodlanamadı.", e); }
    }

    public static Message decode(String frame) throws IOException { return decode(frame, null); }

    public static Message decode(String frame, String password) throws IOException {
        if (frame == null) throw new IOException("Boş çerçeve.");
        if (!frame.startsWith(PREFIX)) return new Message(MessageType.TEXT, frame);
        try {
            byte[] bytes = Base64.getDecoder().decode(frame.substring(PREFIX.length()));
            try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes))) {
                int kind = in.readUnsignedByte();
                if (kind == 5 || kind == 6) return decodeProtected(in, bytes, kind, password);
                String sender=readNullable(in), target=readNullable(in);
                Message result = switch(kind) {
                    case 1 -> new Message(MessageType.FILE_START,sender,target,new FileTransfer.Start(readUuid(in),in.readUTF(),in.readLong()),null);
                    case 2 -> {
                        var id=readUuid(in); int sequence=in.readInt(), length=in.readInt();
                        if (length < 1 || length > FileTransfer.CHUNK_SIZE || length > in.available()) throw new IOException("Geçersiz PDF parçası.");
                        yield new Message(MessageType.FILE_CHUNK,sender,target,new FileTransfer.Chunk(id,sequence,in.readNBytes(length)),null);
                    }
                    case 3 -> new Message(MessageType.FILE_END,sender,target,new FileTransfer.End(readUuid(in),in.readInt()),null);
                    case 4 -> new Message(MessageType.TEXT,sender,target,in.readUTF(),null);
                    default -> throw new IOException("Bilinmeyen çerçeve türü.");
                };
                if (in.available()!=0) throw new IOException("Çerçevede fazladan veri var.");
                return result;
            }
        } catch (IllegalArgumentException | java.io.EOFException e) { throw new IOException("Bozuk mesaj çerçevesi.",e); }
    }

    /** Validates the wire shape; returns plain packets, or null for protected text. */
    public static Message validateForRelay(String frame) throws IOException {
        if (frame == null) throw new IOException("Boş çerçeve.");
        if (!frame.startsWith(PREFIX)) return new Message(MessageType.TEXT, frame);
        byte[] bytes;
        try { bytes=Base64.getDecoder().decode(frame.substring(PREFIX.length())); }
        catch(IllegalArgumentException e) { throw new IOException("Bozuk Base64 çerçevesi.",e); }
        try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(bytes))) {
            int kind=in.readUnsignedByte();
            if(kind==5||kind==6) {
                readNullable(in); readNullable(in);
                if(in.readNBytes(SALT_BYTES).length!=SALT_BYTES) throw new IOException("Salt eksik.");
                int length=in.readInt(); int trailer=kind==6?HMAC_BYTES:0;
                if(length<1||length>in.available()-trailer) throw new IOException("Şifreli içerik uzunluğu geçersiz.");
                in.skipNBytes(length);
                if(in.available()!=trailer) throw new IOException("Şifreli pakette fazladan veya eksik veri var.");
                return null;
            }
        } catch(java.io.EOFException e) { throw new IOException("Eksik çerçeve.",e); }
        return decode(frame);
    }
    private static Message decodeProtected(DataInputStream in, byte[] complete, int kind, String password) throws IOException {
        if (password == null || password.isBlank()) throw new IOException("Şifreli mesaj için aynı parola gerekli.");
        try {
            if (kind == 6) {
                if (complete.length < HMAC_BYTES) throw new IOException("AES-CBC paketi eksik.");
                byte[] authenticated=java.util.Arrays.copyOf(complete,complete.length-HMAC_BYTES);
                byte[] supplied=java.util.Arrays.copyOfRange(complete,complete.length-HMAC_BYTES,complete.length);
                byte[] salt=extractSalt(authenticated);
                CryptoService service=MANUAL_CBC;
                byte[] macKey=service.deriveKey(password+"::frame-mac",salt);
                if (!MessageDigest.isEqual(supplied,hmac(authenticated,macKey))) throw new IOException("AES-CBC mesaj doğrulaması başarısız (parola uyuşmuyor veya veri değişmiş).");
            }
            String sender=readNullable(in), target=readNullable(in);
            byte[] salt=in.readNBytes(SALT_BYTES); if (salt.length!=SALT_BYTES) throw new IOException("Salt eksik.");
            int length=in.readInt(); int macLength=kind==6?HMAC_BYTES:0;
            if (length<1 || length>in.available()-macLength) throw new IOException("Şifreli içerik uzunluğu geçersiz.");
            byte[] encrypted=in.readNBytes(length);
            if (in.available()!=macLength) throw new IOException("Şifreli pakette fazladan veya eksik veri var.");
            if (kind==6) in.skipNBytes(macLength);
            CryptoService service=kind==5?GCM:MANUAL_CBC;
            byte[] key=service.deriveKey(password,salt);
            byte[] plain=kind==5
                    ? ((AesGcmCryptoService)GCM).decrypt(encrypted,key,associatedData((byte)kind,sender,target,salt))
                    : service.decrypt(encrypted,key);
            String text=new String(plain,java.nio.charset.StandardCharsets.UTF_8);
            return new Message(MessageType.TEXT,sender,target,text,null);
        } catch (IOException e) { throw e; }
        catch (Exception e) { throw new IOException("Şifreli metin çözülemedi.",e); }
    }

    private static byte[] extractSalt(byte[] body) throws IOException {
        try (DataInputStream in=new DataInputStream(new ByteArrayInputStream(body))) {
            in.readUnsignedByte(); readNullable(in); readNullable(in); byte[] salt=in.readNBytes(SALT_BYTES);
            if(salt.length!=SALT_BYTES) throw new IOException("Salt eksik."); return salt;
        }
    }
    private static byte[] associatedData(byte kind,String sender,String target,byte[] salt) throws IOException {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        try(DataOutputStream out=new DataOutputStream(bytes)) { out.writeByte(kind); writeNullable(out,sender); writeNullable(out,target); out.write(salt); }
        return bytes.toByteArray();
    }
    private static byte[] encryptedBody(byte kind,String sender,String target,byte[] salt,byte[] encrypted) throws IOException {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        try(DataOutputStream out=new DataOutputStream(bytes)) { out.writeByte(kind); writeNullable(out,sender); writeNullable(out,target); out.write(salt); out.writeInt(encrypted.length); out.write(encrypted); }
        return bytes.toByteArray();
    }
    private static byte[] hmac(byte[] body,byte[] key) throws Exception { Mac mac=Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(key,"HmacSHA256")); return mac.doFinal(body); }
    private static byte[] concat(byte[] a,byte[] b) { byte[] r=java.util.Arrays.copyOf(a,a.length+b.length); System.arraycopy(b,0,r,a.length,b.length); return r; }
    private static CryptoService service(CryptoMode mode) { return mode==CryptoMode.AES_128_GCM?GCM:MANUAL_CBC; }
    private interface PayloadWriter { void write(DataOutputStream out) throws IOException; }
    private static String encodeBinary(byte kind,Message message,PayloadWriter writer) {
        try { ByteArrayOutputStream bytes=new ByteArrayOutputStream(); try(DataOutputStream out=new DataOutputStream(bytes)) { out.writeByte(kind); writeNullable(out,message.senderId()); writeNullable(out,message.targetId()); writer.write(out); }
            return PREFIX+Base64.getEncoder().encodeToString(bytes.toByteArray());
        } catch(IOException e) { throw new IllegalArgumentException("Mesaj kodlanamadı.",e); }
    }
    private static void writeNullable(DataOutputStream out,String value) throws IOException { out.writeUTF(value==null?"":value); }
    private static String readNullable(DataInputStream in) throws IOException { String v=in.readUTF(); return v.isEmpty()?null:v; }
    private static void writeUuid(DataOutputStream out,java.util.UUID id) throws IOException { out.writeLong(id.getMostSignificantBits()); out.writeLong(id.getLeastSignificantBits()); }
    private static java.util.UUID readUuid(DataInputStream in) throws IOException { return new java.util.UUID(in.readLong(),in.readLong()); }
}
