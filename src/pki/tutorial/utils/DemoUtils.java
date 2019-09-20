/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.utils;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import pki.tutorial.crypto.SoftCertificateHolder;
import pki.tutorial.crypto.CryptoOperations;
import pki.tutorial.crypto.SoftKeyStoreHolder;

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
    private static final String TEST_FILE_PATH_DECRYPTED = "C:\\java-pki-tutorial\\outputs\\test1.txt";

    private static final String TEST_FILE_HASH_PATH = "C:\\java-pki-tutorial\\outputs\\test.sha256";
    private static final String TEST_FILE_ENCRYPT_PATH = "C:\\java-pki-tutorial\\outputs\\test.encrypted";

    public static void testGenerateAesKey() throws NoSuchAlgorithmException {
        System.out.println("the key 1 "
                + new String(CryptoUtils.generateAesKey(128).getEncoded()));
        System.out.println("the key 2 "
                + new String(CryptoUtils.generateAesKey(128).getEncoded()));
    }

    public static void testAesEncryptWithFiles() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        int aesKeySize = 128;
        SecretKey aesKey = CryptoUtils.generateAesKey(aesKeySize);

        encryptTestFile(aesKey);

        decryptTestFile(aesKey);

    }

     static void decryptTestFile(SecretKey aesKey) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] chiper_text_from_file = FileManager.readFile(TEST_FILE_ENCRYPT_PATH);

        byte[] decrypted = CryptoUtils.aesDecrypt(chiper_text_from_file, aesKey);

        FileManager.writeFile(decrypted, TEST_FILE_PATH_DECRYPTED);
    }

     static void encryptTestFile(SecretKey aesKey) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] plainText = FileManager.readFile(TEST_FILE_PATH);

        byte[] cihperText = CryptoUtils.aesEncrypt(plainText, aesKey);

        FileManager.writeFile(cihperText, TEST_FILE_ENCRYPT_PATH);
    }

    public static void testCertificates() throws FileNotFoundException, CertificateException {
        SoftCertificateHolder aliCertHolder = new SoftCertificateHolder(CRTIFICATE_PATH);
        aliCertHolder.init();

        SoftCertificateHolder caCertHolder = new SoftCertificateHolder(CA_PATH);
        caCertHolder.init();

        System.out.println("is ali signed by ali key ="
                + aliCertHolder.verifySignKey(aliCertHolder.getPublicKey()));

        System.out.println("is ali signed by Ca key ="
                + aliCertHolder.verifySignKey(caCertHolder.getPublicKey()));

        System.out.println("is Ca signed by Ca key ="
                + caCertHolder.verifySignKey(caCertHolder.getPublicKey()));

        System.out.println("is Ca signed by ali key ="
                + caCertHolder.verifySignKey(aliCertHolder.getPublicKey()));
    }

    public static void testKeyStore() throws KeyStoreException, IOException, FileNotFoundException, NoSuchAlgorithmException, CertificateException {
        SoftKeyStoreHolder keyStoreHolder = new SoftKeyStoreHolder(KEYSTORE_PATH, KEYSTORE_PASS);
        keyStoreHolder.init();
        List<String> aliasList = keyStoreHolder.getAliases();
        if (aliasList.size() > 0) {
            keyStoreHolder.printAliases();
            
            String firstAlias = keyStoreHolder.getAliases().get(0);
            X509Certificate firstCert = keyStoreHolder.getCertificate(firstAlias);

            System.out.println(firstCert.toString());
        }

    }
    
    public static void testGenerateCertificate() throws CertificateEncodingException, IllegalStateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException{
    
        String subjectDn="CN=Almissbah,O=nctr";
        KeyPair keyPair=CryptoUtils.generate1024RsaKeyPair();
        X509Certificate certifcate = CryptoUtils.generateSelfSignedCertificate(keyPair, subjectDn);
}
}
