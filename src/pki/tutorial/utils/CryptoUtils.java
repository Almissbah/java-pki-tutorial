/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.utils;

import pki.tutorial.crypto.*;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author mohammed Almissbah
 */
public class CryptoUtils {

    public static final String ALG_RSA = "RSA";
    public static final String ALG_AES = "AES";
    public static final String ALG_SHA256 = "SHA-256";
    public static final String ALG_SHA256_WITH_RSA = "SHA256WithRSA";
    public static final String ENC_UTF_8 = "UTF-8";

    public static SecretKey generateAesKey(int keyBitSize) throws NoSuchAlgorithmException {
     return CryptoOperations.generateSecretKey(keyBitSize, ALG_AES);
    }

    public static KeyPair generate1024RsaKeyPair() throws NoSuchAlgorithmException {
        return CryptoOperations.generateKeyPair(1024, ALG_RSA);
    }

    public static byte[] aesEncrypt(byte[] data, SecretKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        return CryptoOperations.cipherEncryptMode(data, ALG_AES, key);
    }
    
    public static byte[] aesDecrypt(byte[] cipherText, SecretKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        return CryptoOperations.cipherDecryptMode(cipherText, ALG_AES, key);
    }

    public static byte[] rsaEncrypt(byte[] data, PrivateKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        return CryptoOperations.cipherEncryptMode(data, ALG_RSA, key);
    }

    public static byte[] rsaDecrypt(byte[] cipherText, PublicKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        return CryptoOperations.cipherDecryptMode(cipherText, ALG_RSA, key);
    }

    public static byte[] generateSha256(byte[] data) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return CryptoOperations.generateHash(data, ALG_SHA256);
    }

   
    public static byte[] signDataSha256WithRSA(byte[] data, PrivateKey privateKey) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException, SignatureException {
        return CryptoOperations.signData(data, privateKey, ALG_SHA256_WITH_RSA);
    }

    public static boolean verifySignatureSha256WithRSA(byte[] data,
            PublicKey pubKey, byte[] digitalSignature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        return CryptoOperations.verifySignature(data, pubKey, digitalSignature, ALG_SHA256_WITH_RSA);
    }

    public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair,String subjectDn) throws CertificateEncodingException, IllegalStateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
       return CryptoOperations.generateCertificate(subjectDn, subjectDn, keyPair, keyPair.getPrivate(), ALG_SHA256_WITH_RSA);
    }

    public static byte[] encodeUTF8(String data) throws UnsupportedEncodingException {
        return CryptoOperations.encodeString(data,ENC_UTF_8);
    }
}
