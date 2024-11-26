package com.example;

import java.security.Provider;
import java.security.Security;
import java.util.Iterator;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.*;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author nerijus
 */
public class sauga
{

    private static final String	digits = "0123456789ABCDEF";
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception
    {
        // Savo uzduotis realizuokite kaip klases Main metodus
        // ir juos iskvieskite is sio metodo, kaip pavyzdziui:
        Security.addProvider(new BouncyCastleProvider());
        if (doBCCheck()) doListBCCapabilities();        
        //doSimplePolicyTest();
    }

    /*
input : BABA000000000000 0102030400000000 BABA
cipher: DFD1AD8FED3D091F 79D85F1A0E8F1F61 D98C1A5003FDEE0B 615FC394D8FE1C54  bytes: 32
Naudotas raktas : 6665566666655666 3331133333311333
plain : BABA000000000000 0102030400000000 BABA bytes: 18
*/
    public static void doDecryptSerpent() throws Exception
    {
        byte[]  keyBytes = new byte[] {
                0x66, 0x65, 0x56, 0x66, 0x66, 0x65, 0x56, 0x66,
                0x33, 0x31, 0x13, 0x33, 0x33, 0x31, 0x13, 0x33};
        byte[]  input = Hex.decode ("DFD1AD8FED3D091F 79D85F1A0E8F1F61"+
                                    "D98C1A5003FDEE0B 615FC394D8FE1C54");
        byte[]	ivBytes = Hex.decode ("0706050403020100 08090A0B0C0D0E0F");

        System.out.println("Input : " + toHex(input));
        SecretKeySpec   key = new SecretKeySpec(keyBytes, 0, 16, "serpent");

        Cipher          cipher = Cipher.getInstance("serpent/ECB/NoPadding");

        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = new byte[cipher.getOutputSize(input.length)];

        int ptLength = cipher.update(input, 0, input.length, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        System.out.println("Serpent decrypted message: " + toHex(plainText, ptLength) + " bytes: " + ptLength);
        byte[] raktas = key.getEncoded();
        System.out.println("Used key : " + toHex(raktas));

        //Patikrinimas
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = new byte[cipher.getOutputSize(ptLength)];

        int ctLength = cipher.update(plainText, 0, ptLength, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);

        System.out.println("Cipher text : " + toHex(cipherText, ctLength) + " bytes: " + ctLength);        
    }


    public static void doEncryptSerpent() throws Exception
    {
        
    }

 /**
 * Test to make sure the unrestricted policy files are installed.
 */
    public static void doSimplePolicyTest() throws Exception
    {
        byte[] data = { 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

        // create a 64 bit secret key from raw bytes
        SecretKey key64 = new SecretKeySpec(new byte[] { 0x00, 0x01, 0x02,
                0x03, 0x04, 0x05, 0x06, 0x07 }, "Blowfish");

        // create a cipher and attempt to encrypt the data block with our key
        Cipher c = Cipher.getInstance("Blowfish/ECB/NoPadding");

        c.init(Cipher.ENCRYPT_MODE, key64);
        c.doFinal(data);
        System.out.println("64 bit test: passed");

        // create a 128 bit secret key from raw bytes
        SecretKey key128 = new SecretKeySpec(new byte[] { 0x00, 0x01, 0x02,
                0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                0x0d, 0x0e, 0x0f}, "Blowfish");

        // now try encrypting with the larger key
        c.init(Cipher.ENCRYPT_MODE, key128);
        System.out.println("128 bit test: passed");

        // create a 192 bit secret key from raw bytes
        SecretKey key192 = new SecretKeySpec(new byte[] { 0x00, 0x01, 0x02,
                0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                0x17 }, "Blowfish");

        // now try encrypting with the larger key
        c.init(Cipher.ENCRYPT_MODE, key192);
        c.doFinal(data);
        System.out.println("192 bit test: passed");

        System.out.println("Tests completed");
    }

    /**
      * List the available capabilities for ciphers, key agreement, macs, message
      * digests, signatures and other objects in the BC provider.
    */
    public static void doListBCCapabilities() throws Exception
    {
        Provider	provider = Security.getProvider("BC");
        Iterator        it = provider.keySet().iterator();
        
        while (it.hasNext())
        {
            String	entry = (String)it.next();           
            // this indicates the entry refers to another entry
            if (entry.startsWith("Alg.Alias."))
            {
                entry = entry.substring("Alg.Alias.".length());
            }
            String  factoryClass = entry.substring(0, entry.indexOf('.'));
            String  name = entry.substring(factoryClass.length() + 1);

            System.out.println(factoryClass + ": " + name);
        }
    }
    
    public static boolean doBCCheck()
    {
        // TODO code application logic here
        String name = "BC";
        if (Security.getProvider(name) == null)
        {
            System.out.println("BC not installed");
            return false;
        }
        else
        {
            System.out.println("BC installed");
            return true;
        }        
    }    

    
    /**
     * Du pagalbiniai metodai skirti "graziai" atvaizduoti baitu masyvus
     */
    public static String toHex(byte[] data, int length)
    {
        StringBuffer	buf = new StringBuffer();
        for (int i = 0; i != length; i++)
        {
            int	v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));

            if (((i+1) % 8 == 0) && (i>0)) buf.append(" ");

        }
        return buf.toString();
    }

    public static String toHex(byte[] data)
    {
        return toHex(data, data.length);
    }
    
}