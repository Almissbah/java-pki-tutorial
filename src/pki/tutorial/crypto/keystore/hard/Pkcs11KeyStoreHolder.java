/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.crypto.keystore.hard;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.Security;
import pki.tutorial.crypto.keystore.BaseKeyStoreHolder;
import sun.security.pkcs11.SunPKCS11;

/**
 *
 * @author mohamed
 */
public abstract class Pkcs11KeyStoreHolder extends BaseKeyStoreHolder {

    private final String libPath;
    private final String tokenName;

    Pkcs11KeyStoreHolder(String tokenName, String libPath) {
        super();
        this.libPath = libPath;
        this.tokenName = tokenName;

    }

    @Override
    public void init(String keystorePassword) throws Exception {

        this.mKeyStorePassword = keystorePassword;
        buildKeyStore();
        System.err.println("init Pkcs11KeyStoreHolder");
    }

    private void buildKeyStore() throws Exception {

        String pkcs11ConfigSettings = "name = " + tokenName + "\n" + "library = " + libPath;
        byte[] pkcs11ConfigBytes = pkcs11ConfigSettings.getBytes();
        final ByteArrayInputStream confStream = new ByteArrayInputStream(pkcs11ConfigBytes);

       // instantiate the provider with your config
        SunPKCS11 pkcs11Provider = new SunPKCS11(confStream);
        Security.addProvider(pkcs11Provider);
        mkeyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
        mkeyStore.load(null, this.mKeyStorePassword.toCharArray());

    }

    @Override
    public boolean isHardToken() {
        return true;
    }

}
