package common;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.UUID;
import java.util.function.LongConsumer;

/** PDF'yi belleğe bütünüyle almadan START / CHUNK / END paketleri üretir. */
public final class FileTransferSender {
    @FunctionalInterface
    public interface PacketWriter { void write(Message message) throws IOException; }

    private FileTransferSender() { }

    public static FileTransfer.Start inspect(Path path) throws IOException {
        if (!Files.isRegularFile(path)) throw new IOException("PDF dosyası bulunamadı.");
        FileTransfer.Start start;
        try {
            start = new FileTransfer.Start(UUID.randomUUID(), path.getFileName().toString(), Files.size(path));
        } catch (IllegalArgumentException e) {
            throw new IOException(e.getMessage(), e);
        }
        try (InputStream input = Files.newInputStream(path)) {
            if (!Arrays.equals(input.readNBytes(5), "%PDF-".getBytes(StandardCharsets.US_ASCII))) {
                throw new IOException("Seçilen dosyada PDF başlığı bulunamadı.");
            }
        }
        return start;
    }

    public static void send(Path path, FileTransfer.Start start, String sender, String target,
                            PacketWriter writer, LongConsumer progress) throws IOException {
        try (InputStream input = Files.newInputStream(path)) {
            if (Files.size(path) != start.size()) throw new IOException("Seçilen PDF'nin boyutu değişmiş.");
            writer.write(new Message(MessageType.FILE_START, sender, target, start, null));
            progress.accept(0);
            long sent = 0;
            int sequence = 0;
            byte[] buffer = new byte[FileTransfer.CHUNK_SIZE];
            int length;
            while ((length = input.read(buffer)) != -1) {
                if (length == 0) continue;
                if (length > start.size() - sent) throw new IOException("PDF gönderim sırasında büyüdü.");
                writer.write(new Message(MessageType.FILE_CHUNK, sender, target,
                        new FileTransfer.Chunk(start.fileId(), sequence++, Arrays.copyOf(buffer, length)), null));
                sent += length;
                progress.accept(sent);
            }
            if (sent != start.size()) throw new IOException("PDF gönderim sırasında eksildi.");
            writer.write(new Message(MessageType.FILE_END, sender, target,
                    new FileTransfer.End(start.fileId(), sequence), null));
        }
    }
}
