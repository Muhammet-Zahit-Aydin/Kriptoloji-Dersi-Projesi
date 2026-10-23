package common;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

/** İki istemcinin ortak kullanacağı güvensiz PDF aktarım sözleşmesi. */
public final class FileTransfer {
    public static final int CHUNK_SIZE = 16 * 1024;

    private FileTransfer() { }

    public record Start(UUID fileId, String fileName, long size) implements Serializable {
        public Start {
            Objects.requireNonNull(fileId, "fileId");
            if (fileName == null || fileName.isBlank() || fileName.length() > 255
                    || fileName.contains("/") || fileName.contains("\\") || fileName.contains(":")
                    || fileName.chars().anyMatch(Character::isISOControl)
                    || !fileName.toLowerCase(java.util.Locale.ROOT).endsWith(".pdf")) {
                throw new IllegalArgumentException("Geçerli bir PDF dosya adı gerekli.");
            }
            if (size < 5 || size > (long) Integer.MAX_VALUE * CHUNK_SIZE) {
                throw new IllegalArgumentException("Geçersiz PDF boyutu.");
            }
        }
    }

    public record Chunk(UUID fileId, int sequence, byte[] data) implements Serializable {
        public Chunk {
            Objects.requireNonNull(fileId, "fileId");
            if (sequence < 0 || data == null || data.length == 0 || data.length > CHUNK_SIZE) {
                throw new IllegalArgumentException("Geçersiz dosya parçası.");
            }
            data = data.clone();
        }

        @Override
        public byte[] data() { return data.clone(); }
    }

    public record End(UUID fileId, int chunkCount) implements Serializable {
        public End {
            Objects.requireNonNull(fileId, "fileId");
            if (chunkCount < 1) throw new IllegalArgumentException("Geçersiz parça sayısı.");
        }
    }
}
