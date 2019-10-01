/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.keystore;
 
import java.io.FileNotFoundException;
import java.io.FileOutputStream; 
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import pki.tutorial.certificate.CertificateFactory;
import static pki.tutorial.core.AppConsts.ALG_SHA256_WITH_RSA;
import pki.tutorial.core.CryptoOperations; 

/**
 *
 * @author mohamed
 */
public abstract class BaseKeyStoreHolder implements KeyStoreHolder {

    protected String mKeyStorePassword;
    protected KeyStore mkeyStore;
    protected  KeyStorefactory keyStoreFactory;
    protected  CertificateFactory certificateFactory; 
    public BaseKeyStoreHolder() {
        this.keyStoreFactory = new KeyStorefactory();
        this.certificateFactory=new CertificateFactory();
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
    public void importKeyPair(String alias,PrivateKey privateKey,  Certificate[] chain) throws KeyStoreException {
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
        mkeyStore.setCertificateEntry(alias, certificateFactory.createX509CertificateFromFile(path));
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
    
     public void storeToDrive(String keyStoreOutputPath) throws Exception {
        try (FileOutputStream keyStoreOutputStream = new FileOutputStream(keyStoreOutputPath)) {
            mkeyStore.store(keyStoreOutputStream, mKeyStorePassword.toCharArray());
        }
    }

    @Override
    public byte[] signData(String keyAlias, byte[] data) throws Exception{
        PrivateKey privateKey = getPrivateKey(keyAlias);
     return CryptoOperations.signData(data, privateKey,  ALG_SHA256_WITH_RSA);
 }

    @Override
    public boolean verifySignature(String keyAlias, byte[] data, byte[] signature) throws Exception{
        PublicKey publicKey = getCertificate(keyAlias).getPublicKey();
      return CryptoOperations.verifySignature(data, publicKey, signature,  ALG_SHA256_WITH_RSA); 
    }
     
     

}
