/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.interfaces;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 *
 * @author mohamed
 */
public interface CryptoFileUtil {
    public static final String KEYSTORE_TYPE_PKCS12 = "PKCS12";
    public static final String CERT_TYPE_X509 = "X.509";
    
    Certificate loadCertificate(String path)  throws FileNotFoundException, CertificateException ;
    KeyStore loadKeyStore(String keyStorePath,String KeySotrePassword) throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException ;
    byte[] readFile(String inputFilePath) throws IOException;
    void writeFile(byte[] data, String outPutFilePath) throws IOException;
}
