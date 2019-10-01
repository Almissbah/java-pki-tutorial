/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.certificate;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import pki.tutorial.core.AppConsts; 

/**
 *
 * @author mohamed
 */
public class CertificateFactory {
    
    
   public  X509Certificate createSignedCertificate(String issuerDn,String subjectDn,PublicKey certificatePublicKey,PrivateKey caSignerKey,String signingAlgrithm) throws CertificateEncodingException, IllegalStateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        X509V3CertificateGenerator cert = new X509V3CertificateGenerator();
        cert.setSerialNumber(BigInteger.valueOf(1));   //or generate a random number  
        cert.setSubjectDN(new X509Principal(subjectDn));
        cert.setIssuerDN(new X509Principal(issuerDn)); //same since it is self-signed  
        cert.setPublicKey(certificatePublicKey);
        cert.setNotAfter(new Date());
        cert.setNotBefore(new Date());
        cert.setSignatureAlgorithm(signingAlgrithm);
        return cert.generate(caSignerKey);
    }
   
   
      public  X509Certificate createSelfSignedCertificate(String issuerDn,String subjectDn,
              KeyPair keyPair,String signingAlgrithm) throws CertificateEncodingException, IllegalStateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        X509V3CertificateGenerator cert = new X509V3CertificateGenerator();
        cert.setSerialNumber(BigInteger.valueOf(1));   //or generate a random number  
        cert.setSubjectDN(new X509Principal(subjectDn));
        cert.setIssuerDN(new X509Principal(issuerDn)); //same since it is self-signed  
        cert.setPublicKey(keyPair.getPublic());
        cert.setNotAfter(new Date());
        cert.setNotBefore(new Date());
        cert.setSignatureAlgorithm(signingAlgrithm);
        return cert.generate(keyPair.getPrivate());
    }
      
    public  Certificate createCertificateFromFile(String path) throws FileNotFoundException, CertificateException {
        java.security.cert.CertificateFactory certificateFactory = java.security.cert.CertificateFactory.getInstance( AppConsts.CERTIFICATE_TYPE_X509);
        InputStream certificateInputStream = new FileInputStream(path);
        Certificate certificate = certificateFactory.generateCertificate(certificateInputStream);
        return certificate;
    } 
    public  Certificate createCertificateFromFile(String path,String type) throws FileNotFoundException, CertificateException {
        java.security.cert.CertificateFactory certificateFactory = java.security.cert.CertificateFactory.getInstance(type);
        InputStream certificateInputStream = new FileInputStream(path);
        Certificate certificate = certificateFactory.generateCertificate(certificateInputStream);
        return certificate;
    }
      
}
