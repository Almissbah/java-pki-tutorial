/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.ejbca;

import caadminapplication.GenCerteficate;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException; 
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import javax.xml.namespace.QName;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.certificates.crl.RevokedCertInfo;

import org.cesecore.certificates.util.AlgorithmConstants;
import org.ejbca.core.protocol.ws.client.gen.AlreadyRevokedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ApprovalException_Exception;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CADoesntExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.Certificate;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.DateNotValidException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
import org.ejbca.core.protocol.ws.client.gen.EndEntityProfileNotFoundException_Exception;
import org.ejbca.core.protocol.ws.client.gen.IllegalQueryException_Exception;
import org.ejbca.core.protocol.ws.client.gen.KeyStore;
import org.ejbca.core.protocol.ws.client.gen.NameAndId;
import org.ejbca.core.protocol.ws.client.gen.NotFoundException_Exception;
import org.ejbca.core.protocol.ws.client.gen.RevokeBackDateNotAllowedForProfileException_Exception;
import org.ejbca.core.protocol.ws.client.gen.RevokeStatus;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserDoesntFullfillEndEntityProfile_Exception;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.common.KeyStoreHelper;
/**
 *
 * @author mohamed
 */
public class EjbcaWebService {

    private static EjbcaWS ejbcaraws;
   Properties prop;
    private String workingDIRpath;
    public nctrEJBCAwsRA(String ejbcaIPorAddress, String ksPath,
            String password, String workingDIRpath) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        String urlstr = "https://" + ejbcaIPorAddress
                + ":8443/ejbca/ejbcaws/ejbcaws?wsdl";
        ignoreSSLhostname(ejbcaIPorAddress);
        System.out.println("Contacting webservice at " + urlstr);

        System.setProperty("javax.net.ssl.trustStore", ksPath);
        System.setProperty("javax.net.ssl.trustStorePassword", password);

        System.setProperty("javax.net.ssl.keyStore", ksPath);
        System.setProperty("javax.net.ssl.keyStorePassword", password);

        QName qname = new QName("http://ws.protocol.core.ejbca.org/",
                "EjbcaWSService");
        EjbcaWSService service = new EjbcaWSService(new URL(urlstr), qname);
        ejbcaraws = service.getEjbcaWSPort();
    }

    public nctrEJBCAwsRA() throws Exception {

        String ejbcaIPorAddress = "192.168.56.57",ksPath="c:\\p12\\ra-ws-admin.jks", TrustKsPath = "c:\\p12\\ejbcaws.jks", ksPathPassword = "toortoor"
                , TrustKsPathPassword = "toortoor";
        workingDIRpath = "c:\\p12\\";
        
        
                  prop = SettingManager.Load_DB_config_File();
            ejbcaIPorAddress=prop.getProperty("ejbca_hostname");
             ksPath=prop.getProperty("EjbcaKeyStoreLocation");
                        ksPathPassword=prop.getProperty("EjbcaKeyStorePassword");
                   TrustKsPath=prop.getProperty("EjbcaTrustStoreLocation");
                        TrustKsPathPassword=prop.getProperty("EjbcaTrustStorePassword");
                             default_token_password=prop.getProperty("default_token_password");
                         
        ignoreSSLhostname(ejbcaIPorAddress);
        Security.addProvider(new BouncyCastleProvider());

        String urlstr = "https://" + ejbcaIPorAddress
                + ":8443/ejbca/ejbcaws/ejbcaws?wsdl";

        System.out.println("Contacting webservice at " + urlstr);

        System.setProperty("javax.net.ssl.trustStore", TrustKsPath);
        System.setProperty("javax.net.ssl.trustStorePassword", TrustKsPathPassword);
        System.setProperty("javax.net.ssl.keyStore", ksPath);
        System.setProperty("javax.net.ssl.keyStorePassword", ksPathPassword);

        QName qname = new QName("http://ws.protocol.core.ejbca.org/",
                "EjbcaWSService");
        EjbcaWSService service = new EjbcaWSService(new URL(urlstr), qname);
        ejbcaraws = service.getEjbcaWSPort();
    }

    public static void ignoreSSLhostname(String hostname) {
        javax.net.ssl.HttpsURLConnection
                .setDefaultHostnameVerifier((String hostname1, 
                        javax.net.ssl.SSLSession sslSession) -> {
            if (hostname1.equals(hostname1)) {
                return true;
            }
            return false;
        });
    }
    public static boolean userSearch(String username) {
        System.out.print("\nsearching for user " + username + "...\n");
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_CONTAINS);
        usermatch.setMatchvalue(username);
        List<UserDataVOWS> result = null;
        try {
            result = ejbcaraws.findUser(usermatch);
        } catch (AuthorizationDeniedException_Exception
                | EjbcaException_Exception
                | EndEntityProfileNotFoundException_Exception
                | IllegalQueryException_Exception e) {
            // TODO Auto-generated catch block
           return false;
        }
        if (result.size() > 0) {
            System.out.print("user " + username + " exists\n");
            return true;
        } else {
            System.out.print("user " + username + " does not exists\n");
            return false;
        }
    }

    public String userInfo(String username)
            throws AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            CertificateException, NoSuchAlgorithmException, KeyStoreException,
            NoSuchProviderException, IOException {
        String userinfo = "error";
        System.out.print("\nsearching for user " + username + "...\n");
        UserMatch usermatch = new UserMatch();

        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(username);
        List<UserDataVOWS> result = null;
        byte[] userlastcert = null;
        CertificateResponse CertResponse = null;
        try {
            result = ejbcaraws.findUser(usermatch);
            userlastcert = ejbcaraws.findCerts(username, false).get(0)
                    .getRawCertificateData();
            CertResponse = new CertificateResponse(
                    CertificateHelper.RESPONSETYPE_CERTIFICATE, userlastcert);
        } catch (AuthorizationDeniedException_Exception
                | EjbcaException_Exception
                | EndEntityProfileNotFoundException_Exception
                | IllegalQueryException_Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        if (result.size() > 0) {
            userinfo = "\n user DN= " + result.get(0).getSubjectDN()
                    + "\n certificate profile= "
                    + result.get(0).getCertificateProfileName()
                    + "\n endentity profile= "
                    + result.get(0).getEndEntityProfileName() + "\n username= "
                    + result.get(0).getUsername() + "\n CA name= "
                    + result.get(0).getCaName() + "\n issuance date= "
                    + CertResponse.getCertificate().getNotBefore()
                    + "\n email= " + result.get(0).getEmail() + "\n ";

            System.out.print(CertResponse.getCertificate());

            System.out.print(userinfo);

        } else {
            System.out.print("\nuser " + username + " does not exists");
        }
        return userinfo;
    }

    public boolean AddUser(String name, String pass, String userDN, String CAname,
            String crtProfile, String eeProfile, String TokenType, String email) {
        System.out.print("\nadding user " + name + "...");

        if (userSearch(name) == false) {
            System.out.print("\nadding user " + name + "...");
            UserDataVOWS user1 = new UserDataVOWS();
            if (!TokenType.equals("P12")) {
                TokenType = UserDataVOWS.TOKEN_TYPE_USERGENERATED;
            }
            user1.setUsername(name);
            user1.setPassword(pass);
            user1.setClearPwd(false);
            user1.setSubjectDN(userDN);
            user1.setCaName(CAname);
            user1.setEmail(email);
            user1.setEndEntityProfileName(eeProfile);
            user1.setCertificateProfileName(crtProfile);
            user1.setSubjectAltName(null);
            user1.setStatus(10);
            user1.setTokenType(TokenType);

            try {
                ejbcaraws.editUser(user1);
            } catch (ApprovalException_Exception | AuthorizationDeniedException_Exception | CADoesntExistsException_Exception | EjbcaException_Exception | UserDoesntFullfillEndEntityProfile_Exception | WaitingForApprovalException_Exception ex) {
                System.out.print("\nERROR ,user not created");
                System.out.print(ex);

                return false;
            }
            System.out.print("\nuser created successfully !!");
            return true;
        } else {
            System.out.print("\nuser already exists !");
            return true;
        }

    }

    public void AddUser(String name, String pass, String email)
            throws ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            UserDoesntFullfillEndEntityProfile_Exception,
            WaitingForApprovalException_Exception {

        AddUser(name, pass, "CN=" + name, "AdminCA1", "ENDUSER", "EMPTY", "P12", email);
    }

    public void DeleteUser(String name)
            throws AlreadyRevokedException_Exception,
            ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception, WaitingForApprovalException_Exception {
        ejbcaraws.revokeUser(name,
                RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, true);
        System.out.print("\n user :" + name + " is deleted !!");

    }

    public void revokeUser(String name)
            throws AlreadyRevokedException_Exception,
            ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception, WaitingForApprovalException_Exception {

        ejbcaraws.revokeUser(name,
                RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, false);
        System.out.print("\n user :" + name + " is revoked !!");
    }

    public void revokeCert(String issuerDN, String serialno, int reason_id)
            throws AlreadyRevokedException_Exception,
            ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, DateNotValidException_Exception,
            EjbcaException_Exception, NotFoundException_Exception,
            RevokeBackDateNotAllowedForProfileException_Exception,
            WaitingForApprovalException_Exception {
        ejbcaraws.revokeCert(issuerDN, serialno,
                reason_id);

    }

    public void suspendCert(String issuerDN, String serialno)
            throws AlreadyRevokedException_Exception,
            ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, DateNotValidException_Exception,
            EjbcaException_Exception, NotFoundException_Exception,
            RevokeBackDateNotAllowedForProfileException_Exception,
            WaitingForApprovalException_Exception {
        ejbcaraws.revokeCert(issuerDN, serialno,
                RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);

    }

    public void UNsuspendCert(String issuerDN, String serialno)
            throws AlreadyRevokedException_Exception,
            ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, DateNotValidException_Exception,
            EjbcaException_Exception, NotFoundException_Exception,
            RevokeBackDateNotAllowedForProfileException_Exception,
            WaitingForApprovalException_Exception {
        ejbcaraws.revokeCert(issuerDN, serialno,
                RevokedCertInfo.NOT_REVOKED);

    }

    public byte[] GenP12file(String username, String KSpass, String keylength,
            String DIRpath) throws Exception {

        UserMatch usermatch = new UserMatch();
        usermatch
                .setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch
                .setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(username);
        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        System.out.print("\ngenerating p12 for user " + username + "...");
        System.out.print("\n user status=" + userdatas.get(0).getStatus());
        userdatas.get(0).setStatus(10);
        if (userdatas != null && userdatas.get(0).getStatus() == 10) {
            userdatas.get(0).setTokenType("P12");
            ejbcaraws.editUser(userdatas.get(0));

            System.out.print("\n user status=" + userdatas.get(0).getStatus());
            KeyStore ksenv = null;

            ksenv = ejbcaraws.pkcs12Req(username, KSpass, null, keylength,
                    AlgorithmConstants.KEYALGORITHM_RSA);

            java.security.KeyStore k = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", KSpass);

            String filePath = workingDIRpath + username + ".p12";
            File f = new File(filePath);
            if (!f.exists()) {
                f.createNewFile();
            }

//         CertificateResponse   CertResponse = new CertificateResponse(
//                    CertificateHelper.RESPONSETYPE_CERTIFICATE, ksenv.getCertificate().getRawCertificateData());
//            
            FileOutputStream fos = new java.io.FileOutputStream(f);
            fos.write(ksenv.getRawKeystoreData());
            fos.close();

            nctrtoken = new nctrPKI(libPathst3, default_token_password, "1");
            Enumeration<String> aliases;
            aliases = nctrtoken.getkeysAliasis();
            //nctr.getCertHSM("key3");
            System.out.println("keys on the token:");
            // ////////////////////////////////////////////////////////////////////////////////
            /**
             * *************** listing keys test *********************
             */
            while (aliases.hasMoreElements()) {
                System.out.println(aliases.nextElement());
            }
            //	nctrtoken.installcert(ksenv.getRawKeystoreData(), KSpass.toCharArray(), username);
            return ksenv.getRawKeystoreData();
        } else {
            System.out.print("\nERROR USER STATUS IS NOT NEW \n");
        }
        return null;
    }

    public byte[] genCertFromCSR(String csrString, String username) throws Exception {

        System.out.println("generating certificate from csr..");
        // Generate a CSR
        UserMatch usermatch = new UserMatch();
        usermatch
                .setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch
                .setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(username);
        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        // Set some user data
        final UserDataVOWS userData = userdatas.get(0);
        // Issue a certificate
        userData.setStatus(10);
        CertificateResponse response = ejbcaraws.certificateRequest(userData, csrString, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
        System.out.println(response.getCertificate().toString());
        System.out.println("generated successfully..");

        File cert = new File(prop.getProperty("DownloadFolderLocation") + username + ".crt");
        FileOutputStream stream = new FileOutputStream(cert.getPath());
        try {
            stream.write(response.getRawData());
        } finally {
            stream.close();
        }

        return response.getRawData();
    }

    public String GenP12inHSM(String username, String cn, String KSpass, String keylength,
            String DIRpath) throws Exception {

        UserMatch usermatch = new UserMatch();
        usermatch
                .setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch
                .setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(username);
        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        System.out.print("\ngenerating p12 for user " + username + "...");
        System.out.print("\n user status=" + userdatas.get(0).getStatus());
        userdatas.get(0).setStatus(10);
        if (userdatas != null && userdatas.get(0).getStatus() == 10) {
            userdatas.get(0).setTokenType("P12");
            ejbcaraws.editUser(userdatas.get(0));

            System.out.print("\n user status=" + userdatas.get(0).getStatus());
            KeyStore ksenv = null;

            ksenv = ejbcaraws.pkcs12Req(username, KSpass, null, keylength,
                    AlgorithmConstants.KEYALGORITHM_RSA);

            java.security.KeyStore k = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", KSpass);

            System.out.print("\n generated !!");
            nctrtoken = new nctrPKI(libPathbit4id, default_token_password, "0");
            System.out.print("\n init token !!");
            Enumeration<String> aliases;
            aliases = nctrtoken.getkeysAliasis();
            //nctr.getCertHSM("key3");
            System.out.println("keys on the token:");
            // ////////////////////////////////////////////////////////////////////////////////
            /**
             * *************** listing keys test *********************
             */
            while (aliases.hasMoreElements()) {
                System.out.println(aliases.nextElement());
            }
            System.out.println("iserting to token:");
            //    nctrtoken.installcert(ksenv.getRawKeystoreData(), KSpass.toCharArray(), cn);

            java.security.cert.Certificate c = (java.security.cert.Certificate) k.getCertificate(cn);

            System.out.println("genertating Certificate:");

            CertificateResponse CertResponse = new CertificateResponse(
                    CertificateHelper.RESPONSETYPE_CERTIFICATE, c.getEncoded());
            X509Certificate usercert = CertResponse.getCertificate();
            System.out.println("object created:");
            File certf = new File("c:\\RAdownloads\\" + cn + ".crt");
            FileOutputStream stream = new FileOutputStream(certf.getPath());
            try {
                stream.write(usercert.getEncoded());
            } finally {
                stream.close();
            }
            System.out.println("keys insterted to token:");
            return usercert.getSerialNumber().toString(16);
        } else {
            System.out.print("\nERROR USER STATUS IS NOT NEW \n");
            //  GenCerteficate.
        }
        return null;
    }

    public String checkCERTStatus(String username) {

        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_CONTAINS);
        usermatch.setMatchvalue(username);
        List<UserDataVOWS> result = null;
        try {
            result = ejbcaraws.findUser(usermatch);

        } catch (AuthorizationDeniedException_Exception
                | EjbcaException_Exception
                | EndEntityProfileNotFoundException_Exception
                | IllegalQueryException_Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return checkCERTStatus(result.get(0).getCaName(), result.get(0)
                .getCertificateSerialNumber().toString());
    }

    public String checkCERTStatus(String issuerDN, String CRTserialno) {

        RevokeStatus revokestatus = null;
        try {
            revokestatus = ejbcaraws.checkRevokationStatus(issuerDN,
                    CRTserialno);

        } catch (AuthorizationDeniedException_Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (CADoesntExistsException_Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (EjbcaException_Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        if (revokestatus != null) {

            if (revokestatus.getReason() == RevokeStatus.REVOKATION_REASON_CERTIFICATEHOLD) {// Certificate isn't revoked
                return "\n" + CRTserialno + " suspended";
            }

            if (revokestatus.getReason() == RevokeStatus.NOT_REVOKED) {
                // Certificate is revoked
                return "\n" + CRTserialno + " not revoked";

//                   if (revokestatus.getReason() != RevokeStatus.REVOKATION_REASON_CERTIFICATEHOLD)
//                {
//                return "\n" + CRTserialno + " revoked";}
            } else {
                // Certificate isn't revoked
                return "\n" + CRTserialno + " revoked";

            }
        }
        return "else";
    }

    public static String USER_STATUS_NOT_FOUND="not found";
        public static String USER_STATUS_NEW="NEW";
            public static String USER_STATUS_GENERATED="GENERATED";
                public static String USER_STATUS_REVOKED="REVOKED";
        
        
    public String checkUSER(String username) {
        String status = "unknown";
        UserMatch usermatch = new UserMatch();
        usermatch
                .setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch
                .setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(username);
        List<UserDataVOWS> userdatas = null;
        try {
            userdatas = ejbcaraws.findUser(usermatch);
            
              if (userdatas.size() > 0) {
            switch (userdatas.get(0).getStatus()) {
                case 10:
                    System.out.print("\nuser " + username + "  status= NEW");
                    status = "NEW";
                    break;
                case 50:
                    System.out.print("\nuser " + username + "  status=REVOKED");
                    status = "REVOKED";
                    break;
                case 40:
                    System.out.print("\nuser " + username + " status=GENERATED");
                    status = "GENERATED";
                    break;

                default:
                    break;
            }
            return status;
        } else {
            System.out.print("\nuser " + username + " does not exists !!");
        }
              
        } catch (AuthorizationDeniedException_Exception | EjbcaException_Exception | EndEntityProfileNotFoundException_Exception | IllegalQueryException_Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

      
        return status;
    }

    public String getUserlastCertAsAfile(String username) throws IOException,
            AuthorizationDeniedException_Exception, EjbcaException_Exception,
            CertificateException {

        List<Certificate> certs = null;
        certs = ejbcaraws.findCerts(username, false);
        System.out.print(certs.size());
        if (certs.size() > 0) {
            String filePath = workingDIRpath + username + ".crt";
            File f = new File(filePath);
            if (!f.exists()) {
                f.createNewFile();
            }

            FileOutputStream fos = new java.io.FileOutputStream(f);
            fos.write(certs.get(0).getCertificateData());
            fos.close();
        } else {
            System.out.print("user has no " + username + " certificate ..");
        }

        // CertificateResponse a=new
        // CertificateResponse(CertificateHelper.RESPONSETYPE_CERTIFICATE ,
        // certs.get(0).getRawCertificateData());
        // System.out.print(a.getCertificate());
        return filePath;
    }

    public X509Certificate printX509cert(String username) {
        byte[] userlastcert = null;
        CertificateResponse CertResponse = null;
        X509Certificate usercert = null;
        List<Certificate> certs;
        try {
            certs = ejbcaraws.findCerts(username, false);
            int index = 0;
            userlastcert = certs.get(index)
                    .getRawCertificateData();

            CertResponse = new CertificateResponse(
                    CertificateHelper.RESPONSETYPE_CERTIFICATE, userlastcert);
            usercert = CertResponse.getCertificate();
          
        return usercert;
        } catch (AuthorizationDeniedException_Exception
                | EjbcaException_Exception | CertificateException e) {
          
        return usercert;
        }

    }

    public List<NameAndId> getEEprofiles() {
        try {
            return ejbcaraws.getAuthorizedEndEntityProfiles();
        } catch (AuthorizationDeniedException_Exception | EjbcaException_Exception e) {
            // TODO Auto-generated catch block
                return null;
        }
    
    }

    public List<NameAndId> getCertProfiles(int i) {
        try {
            return ejbcaraws.getAvailableCertificateProfiles(i);
        } catch (AuthorizationDeniedException_Exception | EjbcaException_Exception e) {
      return null;
        }
    }

    public List<NameAndId> getCAs() {
        try {
            return ejbcaraws.getAvailableCAs();

        } catch (AuthorizationDeniedException_Exception | EjbcaException_Exception e) { 
             return null;
        }
      
    }
}
