/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.crypto;

import java.io.FileNotFoundException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import pki.tutorial.interfaces.CryptoFileUtil;
import pki.tutorial.interfaces.KeyStoreHolder;
import pki.tutorial.utils.FileManager;

/**
 *
 * @author mohamed
 */
public abstract class BaseKeyStoreHolder implements KeyStoreHolder {

    protected final String mKeyStorePassword;
    protected KeyStore mkeyStore;
    protected final CryptoFileUtil fileUtils;

    public BaseKeyStoreHolder(String keyStorePass) {
        this.mKeyStorePassword = keyStorePass;
        this.fileUtils = new FileManager();
    }

    @Override
    public List<String> getAliases() throws KeyStoreException {
        Enumeration<String> aliases = mkeyStore.aliases();
        List<String> aliasList = new ArrayList<>();
        while (aliases.hasMoreElements()) {
            aliasList.add(aliases.nextElement());
        }
        return aliasList;
    }

    @Override
    public X509Certificate getCertificate(String alias) throws KeyStoreException {
        return (X509Certificate) mkeyStore.getCertificate(alias);
    }

    @Override
    public void printAliases() throws KeyStoreException {
        System.out.println("Printing aliases:");
        List<String> list = getAliases();
        list.forEach((alias) -> {
            System.out.println("alias=" + alias);
        });
    }

    @Override
    public boolean isInitialized() {
        return mkeyStore != null;
    }

    @Override
    public PrivateKey getPrivateKey(String keyAlias) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
        KeyStore.ProtectionParameter entryPassword
                = new KeyStore.PasswordProtection(mKeyStorePassword.toCharArray());
        KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) mkeyStore.getEntry(keyAlias, entryPassword);
        return keyEntry.getPrivateKey();
    }

    @Override
    public void importKeyPair(PrivateKey privateKey, String alias, Certificate[] chain) throws KeyStoreException {
        mkeyStore.setKeyEntry(alias, (Key) privateKey, mKeyStorePassword.toCharArray(), chain);
    }

    @Override
    public Certificate[] getPrivateKeyChain(String keyAlias) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {

        KeyStore.ProtectionParameter entryPassword
                = new KeyStore.PasswordProtection(mKeyStorePassword.toCharArray());
        KeyStore.PrivateKeyEntry key = (KeyStore.PrivateKeyEntry) mkeyStore.getEntry(keyAlias, entryPassword);
        return key.getCertificateChain();
    }

    @Override
    public void importCertificate(String alias, Certificate crt) throws KeyStoreException {
        mkeyStore.setCertificateEntry(alias, crt);
    }

    @Override
    public void importCertificate(String alias, String path) throws KeyStoreException, FileNotFoundException, CertificateException {
        mkeyStore.setCertificateEntry(alias, fileUtils.loadCertificate(path));
    }

    @Override
    public void deleteEntry(String alias) throws KeyStoreException {
        mkeyStore.deleteEntry(alias);
    }

    @Override
    public boolean isEntryExist(String alias) throws KeyStoreException {
        return mkeyStore.isKeyEntry(alias);
    }

    @Override
    public boolean isCertificateExist(String alias) throws KeyStoreException {
        return mkeyStore.isKeyEntry(alias);
    }

    @Override
    public String getInfo() {
        return mkeyStore.getProvider().getInfo();
    }

}
