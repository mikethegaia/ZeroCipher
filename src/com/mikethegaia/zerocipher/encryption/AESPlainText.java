package com.mikethegaia.zerocipher.encryption;

import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author MikeTheGaia
 */
public class AESPlainText extends AESObject
{
    
    private String plainText;
    private String cipherText;
    
    public AESPlainText(String encryptionKey, int mode) throws Exception
    {
        super(encryptionKey, mode);
    }
    
    public void setPlainText(String plainText)
    {
        if (mode == Cipher.ENCRYPT_MODE) this.plainText = plainText;
    }
    
    public void setCipherText(String cipherText)
    {
        if (mode == Cipher.DECRYPT_MODE) this.cipherText = cipherText;
    }
    
    public String encrypt() throws Exception
    {
        if (mode == Cipher.ENCRYPT_MODE) {
            //Obtain the byte representation of plain text
            byte[] textBytes = plainText.getBytes(ENCODING);
            
            //Encrypt the text and concat the cryptogram with the init vector and the salt
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeySpec key = genSecret();
            cipher.init(mode, key, new IvParameterSpec(initVector));
            byte[] cryptedBytes = cipher.doFinal(textBytes);
            byte[] outBytes = genCryptogram(cryptedBytes);
            
            //Encode the result in Base64 and return the string 
            byte[] crypto = Base64.getEncoder().encode(outBytes);
            return new String(crypto);
        } else return "Object in ENCRYPT_MODE";
    }
    
    public String decrypt() throws Exception
    {
        if (mode == Cipher.DECRYPT_MODE) {
            //Decode the cryptogram from Base64 and retrieve the init vector and the salt
            byte[] crypto = Base64.getDecoder().decode(cipherText.getBytes());
            byte[] elements = getIVSaltCrypto(crypto);
            
            //Decrypt the text using the retrieved init vector and salt
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeySpec key = genSecret();
            cipher.init(mode, key, new IvParameterSpec(initVector));
            return new String(cipher.doFinal(elements), ENCODING);
        } else return "Object in DECRYPT_MODE";
    }
    
}
