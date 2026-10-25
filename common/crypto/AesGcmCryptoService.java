package common.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

/** AES-128-GCM with a fresh 96-bit nonce and a 128-bit authentication tag. */
public final class AesGcmCryptoService implements CryptoService {
    private static final int NONCE_BYTES=12, TAG_BITS=128;
    private final SecureRandom random=new SecureRandom();

    @Override public byte[] encrypt(byte[] plaintext,byte[] key) throws Exception { return encrypt(plaintext,key,null); }
    public byte[] encrypt(byte[] plaintext,byte[] key,byte[] aad) throws Exception {
        requireKey(key); byte[] nonce=new byte[NONCE_BYTES]; random.nextBytes(nonce);
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(TAG_BITS,nonce));
        if(aad!=null) cipher.updateAAD(aad);
        byte[] ciphertext=cipher.doFinal(plaintext);
        return ByteBuffer.allocate(nonce.length+ciphertext.length).put(nonce).put(ciphertext).array();
    }

    @Override public byte[] decrypt(byte[] data,byte[] key) throws Exception { return decrypt(data,key,null); }
    public byte[] decrypt(byte[] data,byte[] key,byte[] aad) throws Exception {
        requireKey(key);
        if(data==null||data.length<NONCE_BYTES+TAG_BITS/8) throw new IllegalArgumentException("AES-GCM verisi kısa.");
        ByteBuffer buffer=ByteBuffer.wrap(data); byte[] nonce=new byte[NONCE_BYTES]; buffer.get(nonce);
        byte[] ciphertext=new byte[buffer.remaining()]; buffer.get(ciphertext);
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(TAG_BITS,nonce));
        if(aad!=null) cipher.updateAAD(aad);
        return cipher.doFinal(ciphertext);
    }

    @Override public byte[] deriveKey(String password,byte[] salt) throws Exception {
        if(password==null||password.isEmpty()||salt==null||salt.length<16) throw new IllegalArgumentException("Parola ve en az 16 byte salt gerekli.");
        KeySpec spec=new PBEKeySpec(password.toCharArray(),salt,120_000,128);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }
    private static void requireKey(byte[] key) { if(key==null||key.length!=16) throw new IllegalArgumentException("AES-128 anahtarı 16 byte olmalı."); }
}
