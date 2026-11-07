package common.crypto;

/** İki istemcinin de bağlantı başında seçebileceği anahtar kurma yöntemleri. */
public enum KeyExchangeMethod {
    DH_2048("DH-2048"),
    RSA_2048("RSA-2048");

    private final String label;

    KeyExchangeMethod(String label) {
        this.label = label;
    }

    @Override
    public String toString() {
        return label;
    }
}
