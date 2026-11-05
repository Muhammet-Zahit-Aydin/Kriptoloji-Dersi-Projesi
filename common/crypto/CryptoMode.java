package common.crypto;

/** Encryption choices shared by both desktop clients. */
public enum CryptoMode {
    INSECURE("Ek metin şifrelemesi yok"),
    AES_128_GCM("Ek AES-128-GCM"),
    AES_128_CBC_MANUAL("Ek AES-128-CBC (elle)");

    private final String label;
    CryptoMode(String label) { this.label = label; }
    @Override public String toString() { return label; }
}
