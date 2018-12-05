package com.mikethegaia.zerocipher.encryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author MikeTheGaia
 */
public class AESFile extends AESObject
{
    
    private String file;
    
    public AESFile(String encryptionKey, String file, int mode) throws Exception
    {
        super(encryptionKey, mode);
        this.file = file;
    }
    
    public String encrypt() throws Exception
    {
        if (mode == Cipher.ENCRYPT_MODE) {            
            //Generate a new encryption cipher
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeySpec key = genSecret();
            cipher.init(mode, key, new IvParameterSpec(initVector));

            //Initialize the original file and create a new one
            File original = new File(file);
            String[] fileArray = file.split("\\.");
            String newFileName = fileArray[0] + "." + fileArray[1] + ".zcf";
            File crypted = new File(newFileName);

            //Read bytes from the original file
            FileInputStream in = new FileInputStream(original);
            byte[] inBytes = new byte[(int)original.length()];
            in.read(inBytes);

             //Encrypt the text and concat the cryptogram with the init vector and the salt
            byte[] cryptedBytes = cipher.doFinal(inBytes);
            byte[] outBytes = genCryptogram(cryptedBytes);
            
            //Write the cryptogram into the new file
            FileOutputStream out = new FileOutputStream(crypted);
            out.write(outBytes);
            in.close();
            out.close();

            return "" + crypted;
        } else return "Object in ENCRYPT_MODE";
    }
    
    public String decrypt(String newPath) throws Exception
    {
        if (mode == Cipher.DECRYPT_MODE) {
            //Initialize the crypted file and create a new one
            File crypted = new File(file);
            String[] fileArray = file.split("\\.");
            String[] fileArray2 = fileArray[0].split("\\\\");
            String newFileName = newPath + "\\" + fileArray2[fileArray2.length-1] + "." + fileArray[1];
            File decrypted = new File(newFileName);

            //Read bytes from the crypted file
            FileInputStream in = new FileInputStream(crypted);
            byte[] inBytes = new byte[(int)crypted.length()];
            in.read(inBytes);
            
            //Retrieve the init vector and the salt and decrypt
            byte[] elements = getIVSaltCrypto(inBytes);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeySpec key = genSecret();
            cipher.init(mode, key, new IvParameterSpec(initVector));
            byte[] outBytes = cipher.doFinal(elements);

            //Write the decrypted data into the new file
            FileOutputStream out = new FileOutputStream(decrypted);
            out.write(outBytes);
            in.close();
            out.close();

            return "" + decrypted;
        } else return "Object in DECRYPT_MODE";
    }
    
}
