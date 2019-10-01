/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.utils;

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
public interface FileUtils {
   
    byte[] readFile(String inputFilePath) throws IOException;
    void writeFile(byte[] data, String outPutFilePath) throws IOException;
}
