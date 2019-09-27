/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.keystore.hard;

/**
 *
 * @author mohamed
 */
public class Bit4IdToken extends Pkcs11KeyStoreHolder {

    public static Bit4IdToken INSTANCE;
    public static String TOKEN_LIB = "C:\\java-pki-tutorial\\libs\\bit4id\\bit4npki.dll";
    public static String TOKEN_NAME = "Bit4IdToken";

    private Bit4IdToken() {
        super(TOKEN_NAME, TOKEN_LIB);
    }

    public static Bit4IdToken getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new Bit4IdToken();
        }
        return INSTANCE;
    }

}
