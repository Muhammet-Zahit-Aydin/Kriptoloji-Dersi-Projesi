package common.crypto;

public interface CryptoService {
    byte[] encrypt(byte[] plaintext, byte[] key) throws Exception;
    byte[] decrypt(byte[] cipherTextWithIv, byte[] key) throws Exception;
    byte[] deriveKey(String password, byte[] salt) throws Exception;
}