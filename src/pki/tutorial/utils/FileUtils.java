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

/**
 *
 * @author mohamed
 */
public class FileUtils {
    
public static String PKCS12_KEYSTORE="PKCS12";

    public static KeyStore loadKeyStore(String keyStorePath, String pass) throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(PKCS12_KEYSTORE);
        char[] keyStorePassword = pass.toCharArray();
        try (InputStream keyStoreData = new FileInputStream(keyStorePath)) {
            keyStore.load(keyStoreData, keyStorePassword);
        }
        return keyStore;
    }

    public static byte[] readFile(String inputFilePath) throws IOException {
        byte[] allBytes = Files.readAllBytes(Paths.get(inputFilePath));
        return allBytes;
    }

    public static void writeFile(byte[] data, String path) throws IOException {
        Files.write(Paths.get(path), data);
    }
}
