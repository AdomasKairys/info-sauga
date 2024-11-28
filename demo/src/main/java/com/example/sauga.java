package com.example;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Iterator;
import javafx.util.Pair;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.*;
import org.bouncycastle.pqc.legacy.crypto.ntru.IndexGenerator.BitString;
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

        // byte[] keyBytes = Hex.decode("6665566666655666 3331133333311333");

        // byte[] input = Hex.decode ("BABE000000000000 1011121300000000 00DAF000");

        // byte[] ivBytes = Hex.decode("3206050403020100 08090A0B0C0D0E0F ");

        
        // byte[] inputBytes = Hex.decode("BABE000000010203 0405060708090A0B 00");
        // byte[] hmacBytes = Hex.decode("C32D60D84FEE25F9 CED88E185741F6FC");
        // byte[] macKeyBytes = new byte[] {0x71,0x72,0x33,0x34,0x35,0x36};
        // doAuthenticationCheck(inputBytes, macKeyBytes, hmacBytes, "HMac-MD4");

        //doHashCheck(inputBytes, hashBytes, "MD4");

        //if (doBCCheck()) doListBCCapabilities();  
        
        //String cipherText = doEncryptTwofish(keyBytes, input, ivBytes);

        //byte[] cipherBytes =  Hex.decode(cipherText);

        //String plainText = doEncryptTwofish(keyBytes, cipherBytes, ivBytes);

        //doSimplePolicyTest();



        BigInteger cypherText = new BigInteger("177B800C091435B10B61DF25FB7FE056" + //
                                               "1BCD4B3EEBF90BACCBDEB2B55EA85A55", 16);
        BigInteger privateKey = new BigInteger("58DAD61F256E10CB23A7D5176F806338" + //
                                               "1F092C9DD1F2EAFBC4A8BFB63F8DC3EB", 16);
        BigInteger publicKey = new BigInteger("03", 16);
        BigInteger modulus = new BigInteger("008548412EB8251930B57BBFA3274094" + //
                                            "D5AA6B8FC6180ACB50B914E7A79276B815", 16);
        
        String plainText = doDecryptRSA(cypherText, publicKey, privateKey, modulus);
        
        BigInteger plainTextBigInt = new BigInteger(Hex.decode(plainText));

        doEncryptRSA(plainTextBigInt, publicKey, privateKey, modulus);
    }


     public static Pair<Integer, String> doRSA(byte[] inputBytes, BigInteger publicKey, BigInteger privateKey, BigInteger modulus, int opmode) throws Exception
    {
        int              length = 0;
        SecureRandom     random = new SecureRandom();
        Cipher	         cipher = Cipher.getInstance("RSA/None/ISO9796-1Padding ");
        KeyFactory       keyFactory = KeyFactory.getInstance("RSA");

        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, publicKey);
        RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(modulus, privateKey);

        RSAPublicKey pubKey = (RSAPublicKey)keyFactory.generatePublic(pubKeySpec);
        RSAPrivateKey privKey = (RSAPrivateKey)keyFactory.generatePrivate(privKeySpec);

        cipher.init(opmode, privKey, random);
        byte[] plainText = new byte[cipher.getOutputSize(inputBytes.length)];
        
        length += cipher.doFinal(inputBytes, 0, inputBytes.length, plainText, 0);

        return new Pair<>(length, toHex(plainText, length));
    }
    public static String doDecryptRSA(BigInteger cypherText, BigInteger publicKey, BigInteger privateKey, BigInteger modulus) throws Exception
    {
        byte[] inputBytes = cypherText.toByteArray();
        System.out.println("Input : " + toHex(inputBytes, inputBytes.length));
        Pair<Integer, String> plainText = doRSA(inputBytes, publicKey, privateKey, modulus, Cipher.DECRYPT_MODE);

        System.out.println("RSA decrypted message: " + plainText.getValue() + " bytes: " + plainText.getKey());
        System.out.println("Public key :" + toHex(publicKey.toByteArray()));
        System.out.println("RSA modulus : " + toHex(modulus.toByteArray()));
        System.out.println("Private key : " + toHex(privateKey.toByteArray()));

        return plainText.getValue();
    }

    public static String doEncryptRSA(BigInteger cypherText, BigInteger publicKey, BigInteger privateKey, BigInteger modulus) throws Exception
    {
        byte[] inputBytes = cypherText.toByteArray();
        System.out.println("Input : " + toHex(inputBytes, inputBytes.length));
        Pair<Integer, String> cipherText = doRSA(inputBytes, publicKey, privateKey, modulus, Cipher.ENCRYPT_MODE);

        System.out.println("RSA encrypted message: " + cipherText.getValue() + " bytes: " + cipherText.getKey());
        System.out.println("Public key :" + toHex(publicKey.toByteArray()));
        System.out.println("RSA modulus : " + toHex(modulus.toByteArray()));
        System.out.println("Private key : " + toHex(privateKey.toByteArray()));

        return(cipherText.getValue());
    }



    /*
     HmacSHA1;
     input;BABCE00000010203 0405060708;
     key;5172333435363738 393A3B3C;
     hmac;A8047F7323FAAF00 7ACC628FDEC63CB7 69733FB4;
     maclen;20
     *
     */
    public static void doAuthenticationCheck(byte[]  inputBytes, byte[]  macKeyBytes, byte[]  hmacBytes, String algorithm) throws Exception
    {
        boolean ok = false;


        Mac hMac = Mac.getInstance(algorithm);
        Key hMacKey = new SecretKeySpec(macKeyBytes, algorithm);

        System.out.println("Tekstograma : " + toHex(inputBytes));
        System.out.println("Slaptas raktas : " + toHex(macKeyBytes));
        System.out.println("Pateiktas hmac : " + toHex(hmacBytes));

        hMac.init(hMacKey);
        hMac.update(inputBytes, 0, inputBytes.length);

        byte[] inputMac = new byte[hMac.getMacLength()];
        inputMac = hMac.doFinal();

        System.out.println("Apskaiciuotas hmac : " + toHex(inputMac) + " ilgis " + hMac.getMacLength());

        ok = MessageDigest.isEqual(inputMac, hmacBytes);
        System.out.println("Pranesimas nesuklastotas : " + ok);
    }

    /*
run:
input : BAD0ACE000050607 08090A
hash1 : 2E1ADC2ADAF89305 61CD1F955E17D214 D6564A8D33EF7819
 *
 * 
hash2 : E2748FA046D8CC3A 40E4E9051B5E59EB B977A54122C45614
Message is original : false
BUILD SUCCESSFUL (total time: 0 seconds)
*/

    public static void doHashCheck(byte[] inputBytes, byte[]  hashBytes, String algorithm) throws Exception
    {
        boolean ok = false;

        System.out.println("Tekstograma : " + toHex(inputBytes));
        System.out.println( algorithm+" santrauka : " + toHex(hashBytes));

        MessageDigest   hash = MessageDigest.getInstance(algorithm);

        hash.update(inputBytes, 0, inputBytes.length);
        byte[] inputHash = new byte[hash.getDigestLength()];
        inputHash = hash.digest();

        System.out.println("Apskaičiuota santrauka : " + toHex(inputHash));

        ok = MessageDigest.isEqual(inputHash, hashBytes);
        System.out.println("Tekstogra nepakeista? : " + ok);
    }


    public static Pair<Integer, String> doSerpent(byte[] keyBytes, byte[] input, int opmode) throws Exception
    {
        SecretKeySpec key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "serpent");
        Cipher cipher = Cipher.getInstance("serpent/ECB/NoPadding");

        cipher.init(opmode, key);
        byte[] output = new byte[cipher.getOutputSize(input.length)];
        int outputLength = cipher.update(input, 0, input.length, output, 0);
        outputLength += cipher.doFinal(output, outputLength);

        return new Pair<>(outputLength,toHex(output, outputLength));
    }
  
    public static String doDecryptSerpent(byte[] keyBytes, byte[] input) throws Exception
    {
        System.out.println("Input : " + toHex(input));
        Pair<Integer, String> plainText = doSerpent(keyBytes, input, Cipher.DECRYPT_MODE);

        System.out.println("Serpent decrypted message: " + plainText.getValue() + " bytes: " + plainText.getKey());

        System.out.println("Used key : " + toHex(keyBytes));    

        return(plainText.getValue());
    }

    public static String doEncryptSerpent(byte[] keyBytes, byte[] input) throws Exception
    {
        System.out.println("Input : " + toHex(input));
        Pair<Integer, String> cipherText = doSerpent(keyBytes, input, Cipher.ENCRYPT_MODE);

        System.out.println("Serpent encrypted message: " + cipherText.getValue() + " bytes: " + cipherText.getKey());

        System.out.println("Used key : " + toHex(keyBytes));    

        return(cipherText.getValue());
    }

      
    public static Pair<Integer, String> doTwofish(byte[] keyBytes, byte[] input, byte[] ivBytes, int opmode) throws Exception
    {
        SecretKeySpec key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "twofish");
        Cipher cipher = Cipher.getInstance("twofish/CBC/PKCS7Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes, 0, ivBytes.length);

        cipher.init(opmode, key, ivSpec);
        byte[] output = new byte[cipher.getOutputSize(input.length)];
        int outputLength = cipher.update(input, 0, input.length, output, 0);
        outputLength += cipher.doFinal(output, outputLength);

        return new Pair<>(outputLength,toHex(output, outputLength));
    }

    public static String doDecryptTwofish(byte[] keyBytes, byte[] input, byte[] ivBytes) throws Exception
    {
        System.out.println("Input : " + toHex(input));
        Pair<Integer, String> cipherText = doTwofish(keyBytes, input, ivBytes, Cipher.DECRYPT_MODE);

        System.out.println("Twofish decrypted message: " + cipherText.getValue() + " bytes: " + cipherText.getKey());
        System.out.println("Used key : " + toHex(keyBytes));  
        System.out.println("Used iv : " + toHex(ivBytes));  

        return(cipherText.getValue());
    }

    public static String doEncryptTwofish(byte[] keyBytes, byte[] input, byte[] ivBytes) throws Exception
    {
        System.out.println("Input : " + toHex(input));
        Pair<Integer, String> cipherText = doTwofish(keyBytes, input, ivBytes, Cipher.ENCRYPT_MODE);

        System.out.println("Twofish encrypted message: " + cipherText.getValue() + " bytes: " + cipherText.getKey());
        System.out.println("Used key : " + toHex(keyBytes));  
        System.out.println("Used iv : " + toHex(ivBytes));  

        return(cipherText.getValue());
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