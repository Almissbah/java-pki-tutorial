/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;

/**
 *
 * @author mohamed
 */
public class KeyGenerator {
        public static SecretKey generateSecretKey(int keyBitSize, String algorithm) throws NoSuchAlgorithmException {
        javax.crypto.KeyGenerator keyGenerator = javax.crypto.KeyGenerator.getInstance(algorithm);
        keyGenerator.init(keyBitSize);
        return keyGenerator.generateKey();
    }

    public static KeyPair generateKeyPair(int keySize, String alogrithm) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(alogrithm);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

}
