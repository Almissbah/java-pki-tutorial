/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.crypto.keystore.hard;

/**
 *
 * @author mohamed
 */
public class St3Token extends Pkcs11KeyStoreHolder{
public static St3Token INSTANCE;
public static String TOKEN_LIB="C:\\java-pki-tutorial\\libs\\st3\\st3csp11.dll";
public static String TOKEN_NAME="St3Token";
   private St3Token(String tokenPIN) {
        super(TOKEN_NAME,TOKEN_LIB,tokenPIN);
    }
 public static St3Token getInstance(String keyStorePassword) {
        if (INSTANCE == null) {
            INSTANCE = new St3Token(keyStorePassword);
        }
        return INSTANCE;
    }
    
    
}
