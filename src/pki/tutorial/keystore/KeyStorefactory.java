/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.keystore;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import static pki.tutorial.utils.AppConsts.KEYSTORE_TYPE_PKCS12;

/**
 *
 * @author mohamed
 */
public class KeyStorefactory {

    public KeyStore createKeyStoreFromFile(String keyStorePath, String pass) throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE_PKCS12);
        char[] keyStorePassword = pass.toCharArray();
        try (InputStream keyStoreData = new FileInputStream(keyStorePath)) {
            keyStore.load(keyStoreData, keyStorePassword);
        }
        return keyStore;
    }

    public  KeyStore createNewKeyStore() throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException {

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE_PKCS12);
        keyStore.load(null, null);
        return keyStore;

    }

    public KeyStore createKeyStoreFromFile(String keyStorePath, String pass, String type) throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(type);
        char[] keyStorePassword = pass.toCharArray();
        try (InputStream keyStoreData = new FileInputStream(keyStorePath)) {
            keyStore.load(keyStoreData, keyStorePassword);
        }
        return keyStore;
    }
}
