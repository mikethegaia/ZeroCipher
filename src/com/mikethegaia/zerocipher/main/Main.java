package com.mikethegaia.zerocipher.main;

import com.mikethegaia.zerocipher.encryption.AESFile;
import com.mikethegaia.zerocipher.encryption.AESPlainText;
import java.io.FileNotFoundException;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

/**
 *
 * @author MikeTheGaia
 */
public class Main 
{
    
    public static final String USAGE = "Usage: \njava -jar \"ZeroCipher.jar\" {-f | -t} {-e | -d} <fileOrPath> <password>"
            + "\njava -jar \"ZeroCipher.jar\" -h"
            + "\n   -f: file manipulation"
            + "\n   -t: plain text manipulation"
            + "\n   -e: encryption mode"
            + "\n   -d: decryption mode"
            + "\n   -h: help";
    public static final String CRYPTED_TEXT = "Crypted text: ";
    public static final String DECRYPTED_TEXT = "Decrypted text: ";
    public static final String CRYPTED_FILE = "Crypted file: ";
    public static final String DECRYPTED_FILE = "Decrypted file: ";
    public static final String NEW_DIR = "Directory in which the decrypted file will be stored: ";
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) 
    {
        try 
        {   
            if (args.length != 4 
                    || (args.length == 1 && args[0].equalsIgnoreCase("-h"))  
                    || args[0].charAt(0) != '-' 
                    || args[1].charAt(0) != '-') 
                System.out.println(USAGE);
            else {
                int mode;
                switch (args[1].charAt(1))
                {
                    case 'E':
                    case 'e':
                        mode = Cipher.ENCRYPT_MODE;
                    break;
                    
                    case 'D':
                    case 'd':
                        mode = Cipher.DECRYPT_MODE;
                    break;
                    
                    default:
                         System.out.println(USAGE);
                         return;
                }
                
                switch (args[0].charAt(1))
                {
                    case 'F':
                    case 'f':
                        AESFile cipher = new AESFile(args[3], args[2], mode);
                        if (mode == Cipher.ENCRYPT_MODE) System.out.println(CRYPTED_FILE + cipher.encrypt());
                        else {
                            Scanner scan = new Scanner(System.in);
                            System.out.println(NEW_DIR);
                            String d = scan.nextLine();
                            System.out.println(DECRYPTED_FILE + cipher.decrypt(d));
                        }
                    break;
                    
                    case 'T':
                    case 't':
                        AESPlainText cipher2 = new AESPlainText(args[3], mode);
                        if (mode == Cipher.ENCRYPT_MODE)
                        {
                            cipher2.setPlainText(args[2]);
                            System.out.println(CRYPTED_TEXT + cipher2.encrypt());
                        } else {
                            cipher2.setCipherText(args[2]);
                            System.out.println(DECRYPTED_TEXT + cipher2.decrypt());
                        }
                    break;
                    
                    default:
                         System.out.println(USAGE);
                } 
            }
        } 
        catch (FileNotFoundException e)
        {
            System.out.println("The file " + args[2] + " was not found");
        }
        catch (BadPaddingException | IllegalArgumentException | IllegalBlockSizeException e)
        {
            System.out.println("Incorrect crypted content or password");
        }
        catch (Exception e) 
        {
            e.printStackTrace();
        }
    }
    
}
