/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.keystore;

import java.io.FileNotFoundException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;
import pki.tutorial.keystore.hard.Bit4IdToken;
import pki.tutorial.keystore.hard.St3Token;
import pki.tutorial.keystore.soft.Pkcs12KeyStoreHolder;

/**
 *
 * @author mohamed
 */
public interface KeyStoreHolder {
public static enum KeyStoreHolderType {P12,ST3TOKEN,BIT4ID};

    //Every class should have its own init method
    void init(String keystorePassword) throws Exception;

    Certificate getCertificate(String alias) throws KeyStoreException;

    PrivateKey getPrivateKey(String alias) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException;

    String getInfo();

    List<String> getAliases() throws KeyStoreException;

    void printAliases() throws KeyStoreException;

    boolean isInitialized();

    void importCertificate(String alias, Certificate crt) throws KeyStoreException;

    void importCertificate(String alias, String path) throws KeyStoreException, FileNotFoundException, CertificateException;

    void importKeyPair(String alias, PrivateKey privateKey, Certificate[] chain) throws KeyStoreException;

    boolean isEntryExist(String alias) throws KeyStoreException;

    void deleteEntry(String alias) throws KeyStoreException;

    byte[] signData(String keyAlias, byte[] data) throws Exception;

    boolean verifySignature(String keyAlias, byte[] data, byte[] signature) throws Exception;

    boolean isCertificateExist(String alias) throws KeyStoreException;

    boolean isHardToken();

    void storeToDrive(String keyStoreOutputPath) throws Exception;

    Certificate[] getPrivateKeyChain(String keyAlias) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException;

   

}
