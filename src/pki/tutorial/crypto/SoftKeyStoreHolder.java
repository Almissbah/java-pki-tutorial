/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.crypto;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import pki.tutorial.utils.FileManager;

/**
 *
 * @author mohamed
 */
public class SoftKeyStoreHolder extends BaseKeyStoreHolder{
    
    private final String mKeyStorePath;

    public SoftKeyStoreHolder(String mKeyStorePath, String keyStorePass) {
        super(keyStorePass);
        this.mKeyStorePath = mKeyStorePath;
    }
    
    @Override
    public void init() {
        try {
            mkeyStore= fileUtils.loadKeyStore(mKeyStorePath, mKeyStorePassword);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(SoftKeyStoreHolder.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    

    @Override
    public X509Certificate getCertificate(String alias) throws KeyStoreException{
   return (X509Certificate) mkeyStore.getCertificate(alias);
    }
      
}
