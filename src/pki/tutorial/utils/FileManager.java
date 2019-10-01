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

/**
 *
 * @author mohamed
 */
public class FileManager implements FileUtils{

  

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
