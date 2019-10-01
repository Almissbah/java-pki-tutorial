/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.certificate;

import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.security.cert.X509Certificate; 
import pki.tutorial.utils.FileManager;
import pki.tutorial.utils.FileUtils;
/**
 *
 * @author mohammed Almissbah 
 */
public class SoftCertificateHolder implements CertficateHolder{

    private String mCertificatePath;
    private Certificate mCertificate;
    private final CertificateFactory certificateFactory;
    private final FileUtils fileUtils;
    public SoftCertificateHolder(String path) {
        this.mCertificatePath = path;
        certificateFactory=new CertificateFactory();
        this.fileUtils=new FileManager();
    }

    public SoftCertificateHolder(Certificate mCertificate) {
        this.mCertificate = mCertificate;
        this.certificateFactory=new CertificateFactory();
        this.fileUtils=new FileManager();
    }
    

    public SoftCertificateHolder(String mCertificatePath, CertificateFactory certificateFactory) {
        this.mCertificatePath = mCertificatePath;
        this.certificateFactory = certificateFactory;
        this.fileUtils=new FileManager();
    }
    

    @Override
    public void init() throws FileNotFoundException, CertificateException {
       if(mCertificate==null) mCertificate = certificateFactory.createCertificateFromFile(mCertificatePath);
    }

    @Override
    public PublicKey getPublicKey() {
        return mCertificate.getPublicKey();
    }

    private X509Certificate getX509Certificate() {

        return (X509Certificate) mCertificate;
    }

    @Override
    public String getInfo() {
        X509Certificate crt = getX509Certificate();
        String certificateInfo = "";
        certificateInfo += "\nDN=" + crt.getSubjectDN();
        certificateInfo += "\nissuer DN=" + crt.getIssuerDN();
        return certificateInfo;
    }
    
    @Override
    public boolean verifySignerKey(PublicKey key){
        boolean isVerified=false;
        try {
            mCertificate.verify(key);
            isVerified=true;
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException ex) {
            Logger.getLogger(SoftCertificateHolder.class.getName()).log(Level.SEVERE, null, ex);
        }
        return isVerified;
  }

    @Override
    public void store(String path) throws Exception {
       byte[] crtBytes= mCertificate.getEncoded();
       fileUtils.writeFile(crtBytes, path);
    }
}
