/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.crypto;

/**
 *
 * @author mohamed
 */
public class HardKeyStore extends BaseKeyStoreHolder{
    private static HardKeyStore INSTATNCE;
    public static String libPath = "C:\\Users\\mohamed\\Desktop\\Java PKI Course\\st3\\st3csp11.dll";
    public static String defaultTokenPassword = "12345678";
    public static String slotId = "1";
    public static Pkcs11SlotLabelType slotType = Pkcs11SlotLabelType.SLOT_NUMBER;
    
    private HardKeyStore(String keyStorePass) {
        super(keyStorePass);
    }

    @Override
    public void init() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
}
