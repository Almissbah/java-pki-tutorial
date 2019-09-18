/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.crypto;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author mohamed
 */
public class CryptoUtils {
    
public static String ALG_RSA="RSA";
public static String ALG_AES="AES";
public static String ALG_SHA256="SHA-256";
public static String ALG_SHA256_WITH_RSA="SHA256WithRSA";
public static String ENC_UTF_8="UTF-8";

    public static SecretKey generateAesKey(int keyBitSize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALG_AES);
        keyGenerator.init(keyBitSize);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey;
    }

    public static byte[] aesEncrypt(byte[] data, SecretKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(ALG_AES);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(data);
        return cipherText;
    }
      
        public static  byte[] aesDecrypt(byte[] plainText,SecretKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(ALG_AES);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(plainText);
        return cipherText;
    }
        
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALG_RSA);
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }
    
       public static byte[] rsaEncrypt(byte[] data, PrivateKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(ALG_RSA);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(data);
        return cipherText;
    }
      
        public static  byte[] rsaDecrypt(byte[] plainText,PublicKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(ALG_RSA);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(plainText);
        return cipherText;
    }

       public static byte[] generateSha256(byte[] data) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest messageDigest = 
                MessageDigest.getInstance(ALG_SHA256);
        return messageDigest.digest(data);
    }
    
      
       public byte[] signData(byte[] data,PrivateKey privateKey) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException, SignatureException {
        Signature signature = Signature.getInstance(ALG_SHA256_WITH_RSA);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
     }

    public boolean verifySignature(byte[] data,
            PublicKey pubKey, byte[] digitalSignature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        Signature signature = Signature.getInstance(ALG_SHA256_WITH_RSA);
        signature.initVerify(pubKey);
        signature.update(data);
        return signature.verify(digitalSignature);
    }
      
    public static byte[] encodeUTF8(String data) throws UnsupportedEncodingException {
        return data.getBytes(ENC_UTF_8);
    }
}
