/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import pki.tutorial.utils.DemoUtils;

/**
 *
 * @author mohammed Almissbah 
 * Email : mohammed.almissbah@hotmail.com
 */
public class PkiTutorial {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, FileNotFoundException, CertificateException {
        try {
            // TODO code application logic here
            
            DemoUtils.testGenerateAesKey();
            DemoUtils.testKeyStore();
        } catch (KeyStoreException | IOException ex) {
            Logger.getLogger(PkiTutorial.class.getName()).log(Level.SEVERE, null, ex);
        }
       
    
}}
