/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.demo;

import pki.tutorial.utils.FileManager;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import pki.tutorial.keystore.hard.Bit4IdToken;
import pki.tutorial.certificate.SoftCertificateHolder;
import pki.tutorial.utils.CryptoOperations;
import pki.tutorial.utils.KeyGenerator;
import pki.tutorial.keystore.soft.Pkcs12KeyStoreHolder;
import pki.tutorial.keystore.hard.St3Token;
import pki.tutorial.keystore.KeyStoreHolder;

/**
 *
 * @author mohamed
 */
public class DemoUtils {

    private static final String KEYSTORE_PATH = "C:\\java-pki-tutorial\\crts\\ali.p12";
      private static final String KEYSTORE_OUTPUT_PATH = "C:\\java-pki-tutorial\\outputs\\output.p12";
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
                + new String(DemoCryptoOperations.generateAesKey(128).getEncoded()));
        System.out.println("the key 2 "
                + new String(DemoCryptoOperations.generateAesKey(128).getEncoded()));
    }

    public static void testAesEncryptWithFiles() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        int aesKeySize = 128;
        SecretKey aesKey = DemoCryptoOperations.generateAesKey(aesKeySize);

        encryptTestFile(aesKey);

        decryptTestFile(aesKey);

    }

     static void decryptTestFile(SecretKey aesKey) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] chiper_text_from_file = new FileManager().readFile(TEST_FILE_ENCRYPT_PATH);

        byte[] decrypted = DemoCryptoOperations.aesDecrypt(chiper_text_from_file, aesKey);

        new FileManager().writeFile(decrypted, TEST_FILE_PATH_DECRYPTED);
    }

     static void encryptTestFile(SecretKey aesKey) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] plainText = new FileManager().readFile(TEST_FILE_PATH);

        byte[] cihperText = DemoCryptoOperations.aesEncrypt(plainText, aesKey);

        new FileManager().writeFile(cihperText, TEST_FILE_ENCRYPT_PATH);
    }

    public static void testCertificates() throws FileNotFoundException, CertificateException {
        SoftCertificateHolder aliCertHolder = new SoftCertificateHolder(CRTIFICATE_PATH);
        aliCertHolder.init();

        SoftCertificateHolder caCertHolder = new SoftCertificateHolder(CA_PATH);
        caCertHolder.init();

        System.out.println("is ali signed by ali key ="
                + aliCertHolder.verifySignerKey(aliCertHolder.getPublicKey()));

        System.out.println("is ali signed by Ca key ="
                + aliCertHolder.verifySignerKey(caCertHolder.getPublicKey()));

        System.out.println("is Ca signed by Ca key ="
                + caCertHolder.verifySignerKey(caCertHolder.getPublicKey()));

        System.out.println("is Ca signed by ali key ="
                + caCertHolder.verifySignerKey(aliCertHolder.getPublicKey()));
    }

    public static void testKeyStore() throws KeyStoreException, IOException, FileNotFoundException, NoSuchAlgorithmException, CertificateException, Exception {
        KeyStoreHolder keyStoreHolder=new KeyStoreHolder.Factory().getPkcs12KeyStore(KEYSTORE_PATH);
        //keyStoreHolder = new Pkcs12KeyStoreHolder(KEYSTORE_PATH);
        // keyStoreHolder = St3Token.getInstance("12345678");
                keyStoreHolder.init(KEYSTORE_PASS);
        
        if(keyStoreHolder.isInitialized()){
        List<String> aliasList = keyStoreHolder.getAliases();
        if (aliasList.size() > 0) {
            keyStoreHolder.printAliases();
            
            String firstAlias = keyStoreHolder.getAliases().get(0);
            X509Certificate firstCert = (X509Certificate) keyStoreHolder.getCertificate(firstAlias);

            System.out.println(firstCert.toString());
        }
        
        String subjectDn="CN=Almissbah,O=nctr";
        KeyPair keyPair=DemoCryptoOperations.generate1024RsaKeyPair();
        X509Certificate certifcate = DemoCryptoOperations.generateSelfSignedCertificate(keyPair, subjectDn);
        
        keyStoreHolder.importKeyPair(subjectDn, keyPair.getPrivate(), new Certificate[]{certifcate});
       // keyStoreHolder.importCertificate(subjectDn, certifcate);
        keyStoreHolder.storeToDrive(KEYSTORE_OUTPUT_PATH);
        }
    }
    
    public static void testGenerateCertificate() throws CertificateEncodingException, IllegalStateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException{
    
        String subjectDn="CN=Almissbah,O=nctr";
        KeyPair keyPair=DemoCryptoOperations.generate1024RsaKeyPair();
        X509Certificate certifcate = DemoCryptoOperations.generateSelfSignedCertificate(keyPair, subjectDn);
}
}
