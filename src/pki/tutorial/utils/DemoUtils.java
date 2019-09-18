/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.utils;

import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import pki.tutorial.crypto.CryptoUtils;


/**
 *
 * @author mohamed
 */
public class DemoUtils {

  
    public static void testGenerateAES() throws NoSuchAlgorithmException{
          System.out.println("the key 1 " + 
                  new String(CryptoUtils.generateAesKey(128).getEncoded()));
                System.out.println("the key 2 " +
                        new String(CryptoUtils.generateAesKey(128).getEncoded())); 
    }
}
