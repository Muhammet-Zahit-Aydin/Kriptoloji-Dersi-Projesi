package common.crypto;

/** Encryption choices shared by both desktop clients. */
public enum CryptoMode {
    INSECURE("Güvensiz"),
    AES_128_GCM("AES-128-GCM (kütüphane)"),
    AES_128_CBC_MANUAL("AES-128-CBC (elle)");

    private final String label;
    CryptoMode(String label) { this.label = label; }
    @Override public String toString() { return label; }
}
