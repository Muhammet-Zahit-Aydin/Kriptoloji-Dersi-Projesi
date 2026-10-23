package common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UTFDataFormatException;
import java.util.Base64;
import java.util.UUID;

/** Mevcut readUTF/writeUTF metin taşımasına dosya paketlerini ekler. */
public final class InsecureFrameCodec {
    private static final String PREFIX = "\u001eKRIPTO1:";
    private static final int START = 1, CHUNK = 2, END = 3, TEXT = 4;

    private InsecureFrameCodec() { }

    public static String encode(Message message) throws IOException {
        if (message.type() == MessageType.TEXT && message.payload() instanceof String text
                && !text.startsWith(PREFIX)) {
            checkLength(text);
            return text; // Client-1'in mevcut düz metin biçimi aynen korunur.
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            int kind = switch (message.type()) {
                case FILE_START -> START;
                case FILE_CHUNK -> CHUNK;
                case FILE_END -> END;
                case TEXT -> TEXT;
                default -> throw new IOException("Bu güvensiz çerçeve tipi desteklenmiyor.");
            };
            out.writeByte(kind);
            out.writeUTF(message.senderId() == null ? "" : message.senderId());
            out.writeUTF(message.targetId() == null ? "" : message.targetId());
            switch (kind) {
                case START -> {
                    FileTransfer.Start start = (FileTransfer.Start) message.payload();
                    writeId(out, start.fileId());
                    out.writeUTF(start.fileName());
                    out.writeLong(start.size());
                }
                case CHUNK -> {
                    FileTransfer.Chunk chunk = (FileTransfer.Chunk) message.payload();
                    writeId(out, chunk.fileId());
                    out.writeInt(chunk.sequence());
                    byte[] data = chunk.data();
                    out.writeInt(data.length);
                    out.write(data);
                }
                case END -> {
                    FileTransfer.End end = (FileTransfer.End) message.payload();
                    writeId(out, end.fileId());
                    out.writeInt(end.chunkCount());
                }
                case TEXT -> out.writeUTF((String) message.payload());
                default -> throw new IOException("Geçersiz çerçeve tipi.");
            }
        } catch (ClassCastException | NullPointerException e) {
            throw new IOException("Mesaj tipi ve içeriği uyuşmuyor.", e);
        }
        String frame = PREFIX + Base64.getEncoder().encodeToString(bytes.toByteArray());
        checkLength(frame);
        return frame;
    }

    public static Message decode(String frame) throws IOException {
        if (!frame.startsWith(PREFIX)) return new Message(MessageType.TEXT, frame);
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(
                Base64.getDecoder().decode(frame.substring(PREFIX.length()))))) {
            int kind = in.readUnsignedByte();
            String sender = in.readUTF();
            String target = in.readUTF();
            MessageType type;
            Object payload;
            switch (kind) {
                case START -> {
                    type = MessageType.FILE_START;
                    payload = new FileTransfer.Start(readId(in), in.readUTF(), in.readLong());
                }
                case CHUNK -> {
                    type = MessageType.FILE_CHUNK;
                    UUID id = readId(in);
                    int sequence = in.readInt();
                    int length = in.readInt();
                    if (length < 1 || length > FileTransfer.CHUNK_SIZE) {
                        throw new IOException("Dosya parçasının boyutu geçersiz.");
                    }
                    byte[] data = new byte[length];
                    in.readFully(data);
                    payload = new FileTransfer.Chunk(id, sequence, data);
                }
                case END -> {
                    type = MessageType.FILE_END;
                    payload = new FileTransfer.End(readId(in), in.readInt());
                }
                case TEXT -> {
                    type = MessageType.TEXT;
                    payload = in.readUTF();
                }
                default -> throw new IOException("Bilinmeyen güvensiz çerçeve tipi.");
            }
            if (in.available() != 0) throw new IOException("Çerçevenin sonunda beklenmeyen veri var.");
            return new Message(type, sender.isEmpty() ? null : sender,
                    target.isEmpty() ? null : target, payload, null);
        } catch (IllegalArgumentException e) {
            throw new IOException("Geçersiz dosya çerçevesi: " + e.getMessage(), e);
        }
    }

    private static void writeId(DataOutputStream out, UUID id) throws IOException {
        out.writeLong(id.getMostSignificantBits());
        out.writeLong(id.getLeastSignificantBits());
    }

    private static UUID readId(DataInputStream in) throws IOException {
        return new UUID(in.readLong(), in.readLong());
    }

    private static void checkLength(String text) throws UTFDataFormatException {
        long bytes = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            bytes += c >= 1 && c <= 127 ? 1 : c <= 2047 ? 2 : 3;
        }
        if (bytes > 65535) {
            throw new UTFDataFormatException("Mesaj, writeUTF sınırı olan 65535 byte'ı aşıyor.");
        }
    }
}
