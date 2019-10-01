/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.keystore;
import pki.tutorial.keystore.KeyStoreHolder.KeyStoreHolderType;
import pki.tutorial.keystore.hard.Bit4IdToken;
import pki.tutorial.keystore.hard.St3Token;
import pki.tutorial.keystore.soft.Pkcs12KeyStoreHolder;

/**
 *
 * @author mohamed
 */
public class KeyStoreHolderFactory {
    

        public KeyStoreHolder createPkcs12KeyStore(String filePath) {
            return new Pkcs12KeyStoreHolder(filePath);
        }

        public KeyStoreHolder createPkcs11KeyStore(KeyStoreHolderType keyStoreType) {
            if (keyStoreType.equals(KeyStoreHolderType.ST3TOKEN)) {
                return St3Token.getInstance();
            } else {
                return Bit4IdToken.getInstance();
            }
        }

    
    
}
