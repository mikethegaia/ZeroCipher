package com.mikethegaia.zerocipher.encryption;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author MikeTheGaia
 */
public abstract class AESObject 
{
    
    private static final String ALLOWED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+";
    private static final String HASH_FUNCTION = "SHA-256";
    private static final String SK_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String SK2_ALGORITHM = "AES";
    protected static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    protected static final String ENCODING = "UTF-8";
    protected static final int BLOCK_SIZE = 16;
    protected static final int SALT_SIZE = 8;
    
    protected String initVector;
    protected String encryptionKey;
    protected String salt;
    protected int mode;
    
    protected AESObject (String encryptionKey, int mode) throws Exception
    {
        this.initVector = (mode == Cipher.ENCRYPT_MODE) ? genRandomString(BLOCK_SIZE) : null;
        this.salt = (mode == Cipher.ENCRYPT_MODE) ? genRandomString(SALT_SIZE) : null;
        MessageDigest md = MessageDigest.getInstance(HASH_FUNCTION);
        md.update(encryptionKey.getBytes(ENCODING));
        this.encryptionKey = new String(md.digest());
        this.mode = mode;
    }
    
    private String genRandomString(int size)
    {
        SecureRandom random = new SecureRandom();
        StringBuilder randomString = new StringBuilder();
        while (randomString.length() < size) randomString.append(ALLOWED.charAt(random.nextInt(ALLOWED.length())));
        return randomString.toString();
    }
    
    protected SecretKeySpec genSecret(byte[] salt) throws Exception
    {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(encryptionKey.toCharArray(), salt, 65536, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(SK_ALGORITHM);
        SecretKey secretKey = factory.generateSecret(pbeKeySpec);
        return new SecretKeySpec(secretKey.getEncoded(), SK2_ALGORITHM);
    }
    
    protected byte[] genCryptogram(byte[] initVectorBytes, byte[] saltBytes, byte[] cryptedBytes)
    {
        byte[] outBytes = new byte[BLOCK_SIZE + SALT_SIZE + cryptedBytes.length];
        for (int i = 0; i<BLOCK_SIZE; i++) outBytes[i] = initVectorBytes[i];
        for (int i = BLOCK_SIZE; i<BLOCK_SIZE + SALT_SIZE; i++) outBytes[i] = saltBytes[i- BLOCK_SIZE];
        for (int i = BLOCK_SIZE + SALT_SIZE; i<outBytes.length; i++) outBytes[i] = cryptedBytes[i - (BLOCK_SIZE + SALT_SIZE)];
        return outBytes;
    }
    
    protected byte[][] getIVSaltCrypto(byte[] cryptogram)
    {
        byte[] initVectorBytes = Arrays.copyOfRange(cryptogram, 0, BLOCK_SIZE);
        byte[] saltBytes = Arrays.copyOfRange(cryptogram, BLOCK_SIZE, BLOCK_SIZE + SALT_SIZE);
        byte[] cryptedBytes = Arrays.copyOfRange(cryptogram, BLOCK_SIZE + SALT_SIZE, cryptogram.length);
        byte[][] matrix = { initVectorBytes, saltBytes, cryptedBytes };
        return matrix;
    }
    
}
