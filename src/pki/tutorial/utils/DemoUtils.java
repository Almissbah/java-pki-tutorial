/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.utils;

import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import pki.tutorial.crypto.CryptoUtils;


/**
 *
 * @author mohamed
 */
public class DemoUtils {
    private static final String KEYSTORE_PATH = "C:\\java-pki-tutorial\\crts\\ali.p12";
    private static final String CRTIFICATE_PATH = "C:\\java-pki-tutorial\\crts\\ali.crt";
    
    private static final String CA_PATH = "C:\\java-pki-tutorial\\crts\\ca.cer";
    private static final String KEYSTORE_PASS = "toortoor";
    private static final String KEYSTORE_ALIAS = "ali";
    
    private static final String TEST_FILE_PATH = "C:\\java-pki-tutorial\\outputs\\test.txt";
    private static final String TEST_FILE_HASH_PATH = "C:\\java-pki-tutorial\\outputs\\test.sha256";
    private static final String TEST_FILE_ENCRYPT_PATH = "C:\\java-pki-tutorial\\outputs\\test.encrypted";

  
    public static void testGenerateAES() throws NoSuchAlgorithmException{
          System.out.println("the key 1 " + 
                  new String(CryptoUtils.generateAesKey(128).getEncoded()));
                System.out.println("the key 2 " +
                        new String(CryptoUtils.generateAesKey(128).getEncoded())); 
    }
}
