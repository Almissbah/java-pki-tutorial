/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.certificate;

import java.io.FileNotFoundException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
/**
 *
 * @author mohamed
 */
public interface CertficateHolder {
    void init() throws FileNotFoundException, CertificateException;
    String getInfo();
    PublicKey getPublicKey();
    boolean verifySignerKey(PublicKey key);
}
