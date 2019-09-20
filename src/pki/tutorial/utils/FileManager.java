/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;
import pki.tutorial.interfaces.CryptoFileUtil;

/**
 *
 * @author mohamed
 */
public class FileManager implements CryptoFileUtil{

    private String keyStoreType;
    private String certType;
    public FileManager() {
        this.keyStoreType=CryptoFileUtil.KEYSTORE_TYPE_PKCS12;
        this.certType=CryptoFileUtil.CERT_TYPE_X509;
    }

  

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    public String getCertType() {
        return certType;
    }

    public void setCertType(String certType) {
        this.certType = certType;
    }

    @Override
    public  KeyStore loadKeyStore(String keyStorePath, String pass) throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        char[] keyStorePassword = pass.toCharArray();
        try (InputStream keyStoreData = new FileInputStream(keyStorePath)) {
            keyStore.load(keyStoreData, keyStorePassword);
        }
        return keyStore;
    }

    @Override
    public  Certificate loadCertificate(String path) throws FileNotFoundException, CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance(certType);
        InputStream certificateInputStream = new FileInputStream(path);
        Certificate certificate = certificateFactory.generateCertificate(certificateInputStream);
        return certificate;
    }

    @Override
    public  byte[] readFile(String inputFilePath) throws IOException {
        byte[] allBytes = Files.readAllBytes(Paths.get(inputFilePath));
        return allBytes;
    }

    @Override
    public  void writeFile(byte[] data, String path) throws IOException {
        Files.write(Paths.get(path), data);
    }
}
