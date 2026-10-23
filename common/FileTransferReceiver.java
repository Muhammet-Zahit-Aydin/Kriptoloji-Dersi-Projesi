package common;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/** Eksik dosyayı geçici alanda tutar; yalnızca doğrulanmış END ile kayda hazırlar. */
public final class FileTransferReceiver implements AutoCloseable {
    private FileTransfer.Start start;
    private Path temporary;
    private OutputStream output;
    private long received;
    private int sequence;

    public synchronized void start(FileTransfer.Start metadata) throws IOException {
        if (start != null) throw new IOException("Önceki PDF aktarımı henüz bitmedi.");
        Path path = Files.createTempFile("kriptoloji-pdf-", ".part");
        try {
            output = Files.newOutputStream(path);
            temporary = path;
            start = metadata;
            received = 0;
            sequence = 0;
        } catch (IOException e) {
            Files.deleteIfExists(path);
            throw e;
        }
    }

    public synchronized void append(FileTransfer.Chunk chunk) throws IOException {
        if (start == null || !start.fileId().equals(chunk.fileId()) || chunk.sequence() != sequence) {
            throw new IOException("PDF kimliği veya parça sırası uyuşmuyor.");
        }
        byte[] data = chunk.data();
        if (data.length > start.size() - received) throw new IOException("PDF bildirilen boyutu aşıyor.");
        output.write(data);
        received += data.length;
        sequence++;
    }

    public synchronized ReceivedFile finish(FileTransfer.End end) throws IOException {
        if (start == null || !start.fileId().equals(end.fileId())
                || end.chunkCount() != sequence || received != start.size()) {
            throw new IOException("PDF bitiş bilgisi, boyutu veya parça sayısı uyuşmuyor.");
        }
        output.close();
        output = null;
        try (InputStream input = Files.newInputStream(temporary)) {
            if (!Arrays.equals(input.readNBytes(5), "%PDF-".getBytes(StandardCharsets.US_ASCII))) {
                throw new IOException("Gelen dosyada PDF başlığı bulunamadı.");
            }
        }
        ReceivedFile completed = new ReceivedFile(start, temporary);
        temporary = null; // Geçici dosyanın sahipliği artık ReceivedFile'da.
        start = null;
        return completed;
    }

    public synchronized FileTransfer.Start metadata() { return start; }
    public synchronized long receivedBytes() { return received; }

    @Override
    public synchronized void close() throws IOException {
        try {
            if (output != null) output.close();
        } finally {
            output = null;
            start = null;
            if (temporary != null) {
                Files.deleteIfExists(temporary);
                temporary = null;
            }
        }
    }

    public static final class ReceivedFile implements AutoCloseable {
        private final FileTransfer.Start metadata;
        private final Path temporary;

        private ReceivedFile(FileTransfer.Start metadata, Path temporary) {
            this.metadata = metadata;
            this.temporary = temporary;
        }

        public FileTransfer.Start metadata() { return metadata; }

        /** Var olan bir dosyayı sessizce ezmez; başarısız kayıtta geçici kopya korunur. */
        public synchronized void saveTo(Path destination) throws IOException {
            Files.copy(temporary, destination);
        }

        @Override
        public synchronized void close() throws IOException { Files.deleteIfExists(temporary); }

        @Override
        public String toString() { return metadata.fileName() + " (" + metadata.size() + " byte)"; }
    }
}
