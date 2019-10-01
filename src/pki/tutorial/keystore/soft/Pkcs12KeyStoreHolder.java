/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.keystore.soft;

import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import pki.tutorial.keystore.BaseKeyStoreHolder;

/**
 *
 * @author mohamed
 */
public class Pkcs12KeyStoreHolder extends BaseKeyStoreHolder{
    
    private final String mKeyStorePath;

    public Pkcs12KeyStoreHolder(String mKeyStorePath) {
        super();
        this.mKeyStorePath = mKeyStorePath;
    }
   
    
    
    @Override
    public void init(String mKeyStorePassword) throws Exception {
         System.err.println("init Pkcs11KeyStoreHolder");
            this.mKeyStorePassword=mKeyStorePassword;
            mkeyStore= keyStoreFactory.createKeyStoreFromFile(mKeyStorePath, mKeyStorePassword);
           
        
    }
    

    @Override
    public X509Certificate getCertificate(String alias) throws KeyStoreException{
   return (X509Certificate) mkeyStore.getCertificate(alias);
    }

    @Override
    public boolean isHardToken() {
        return false;}
      
}
