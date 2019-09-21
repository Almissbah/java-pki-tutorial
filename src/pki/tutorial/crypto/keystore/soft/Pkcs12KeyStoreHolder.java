/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.crypto.keystore.soft;

import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import pki.tutorial.crypto.keystore.BaseKeyStoreHolder;

/**
 *
 * @author mohamed
 */
public class Pkcs12KeyStoreHolder extends BaseKeyStoreHolder{
    
    private final String mKeyStorePath;

    public Pkcs12KeyStoreHolder(String mKeyStorePath, String keyStorePass) {
        super(keyStorePass);
        this.mKeyStorePath = mKeyStorePath;
    }
   
    
    @Override
    public void init() {
        try {
            mkeyStore= fileUtils.loadKeyStore(mKeyStorePath, mKeyStorePassword);
        } catch (Exception ex) {
            Logger.getLogger(Pkcs12KeyStoreHolder.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    

    @Override
    public X509Certificate getCertificate(String alias) throws KeyStoreException{
   return (X509Certificate) mkeyStore.getCertificate(alias);
    }

    @Override
    public boolean isHardToken() {
        return false;   }
      
}
