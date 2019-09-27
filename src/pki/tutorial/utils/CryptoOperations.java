/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.utils;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 *
 * @author mohammed Almissbah
 */
public class CryptoOperations {
    public static final String ALG_RSA = "RSA";
    public static final String ALG_AES = "AES";
    public static final String ALG_SHA256 = "SHA-256";
    public static final String ALG_SHA256_WITH_RSA = "SHA256WithRSA";
    public static final String ENC_UTF_8 = "UTF-8";
    
    public static byte[] cipherEncryptMode(byte[] data, String algorithm, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return cipherOperation(data, algorithm, key, Cipher.ENCRYPT_MODE);
    }

    public static byte[] cipherDecryptMode(byte[] data, String algorithm, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return cipherOperation(data, algorithm, key, Cipher.DECRYPT_MODE);
    }

    private static byte[] cipherOperation(byte[] data, String algorithm, Key key, int mode) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(mode, key);
        byte[] cipherText = cipher.doFinal(data);
        return cipherText;
    }


    public static byte[] generateHash(byte[] data, String algorithm) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest messageDigest
                = MessageDigest.getInstance(algorithm);
        return messageDigest.digest(data);
    }


    public static byte[] signData(byte[] data, PrivateKey privateKey, String algorithm) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException, SignatureException {
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }



    public static boolean verifySignature(byte[] data,
            PublicKey pubKey, byte[] digitalSignature, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(pubKey);
        signature.update(data);
        return signature.verify(digitalSignature);
    }

           
    public static X509Certificate generateCertificate(String issuerDn,String subjectDn,KeyPair keyPair,PrivateKey signerKey,String signingAlgrithm) throws CertificateEncodingException, IllegalStateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        X509V3CertificateGenerator cert = new X509V3CertificateGenerator();
        cert.setSerialNumber(BigInteger.valueOf(1));   //or generate a random number  
        cert.setSubjectDN(new X509Principal(subjectDn));
        cert.setIssuerDN(new X509Principal(issuerDn)); //same since it is self-signed  
        cert.setPublicKey(keyPair.getPublic());
        cert.setNotAfter(new Date());
        cert.setNotBefore(new Date());
        cert.setSignatureAlgorithm(signingAlgrithm);
        return cert.generate(signerKey);
    }

    public static byte[] encodeString(String data,String encoding) throws UnsupportedEncodingException {
        return data.getBytes(encoding);
    }
}
