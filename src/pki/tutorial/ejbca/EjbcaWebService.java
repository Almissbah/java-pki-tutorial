/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pki.tutorial.ejbca;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
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
import pki.tutorial.keystore.KeyStoreHolder;
import pki.tutorial.keystore.soft.InMemoryKeyStoreHolder;
import pki.tutorial.utils.FileManager;
import pki.tutorial.utils.FileUtils;

/**
 *
 * @author mohamed
 */
public class EjbcaWebService {

    private static EjbcaWS mEjbcaraWs;
    private Properties prop;
    private FileUtils fileUtils = new FileManager();
    private String workingDirPath = "c:\\EjbcaClient\\";

    public enum CertificateStatus {

        ACTIVE, SUSPENDED, REVOKED, UNKNOWN
    }

    public enum UserStatus {

        NEW, GENERATED, REVOKED, NOT_FOUND, UNKNOWN, EXSISTS
    }

    public EjbcaWebService(String ejbcaIPorAddress, String keystorePath,
            String keyStorePassword, String workingDirPath) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        buildEjbcaWs(ejbcaIPorAddress, keystorePath, keyStorePassword);
    }

    private void buildEjbcaWs(String ejbcaIPorAddress, String keystorePath,
            String keyStorePassword) throws MalformedURLException {
        String urlstr = "https://" + ejbcaIPorAddress
                + ":8443/ejbca/ejbcaws/ejbcaws?wsdl";

        setUpSSL(ejbcaIPorAddress, keystorePath, keyStorePassword);
        QName qname = new QName("http://ws.protocol.core.ejbca.org/",
                "EjbcaWSService");
        EjbcaWSService service = new EjbcaWSService(new URL(urlstr), qname);
        mEjbcaraWs = service.getEjbcaWSPort();

        System.out.println("Contacting webservice at " + urlstr);
    }

    void setUpSSL(String ejbcaIPorAddress, String keystorePath,
            String keyStorePassword) {
        ignoreSSLhostname(ejbcaIPorAddress);

        System.setProperty("javax.net.ssl.trustStore", keystorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", keyStorePassword);

        System.setProperty("javax.net.ssl.keyStore", keystorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", keyStorePassword);
    }

    public static void ignoreSSLhostname(String hostname) {
        javax.net.ssl.HttpsURLConnection
                .setDefaultHostnameVerifier((String hostname1, javax.net.ssl.SSLSession sslSession) -> {
                    return hostname1.equals(hostname1);
                });
    }

    public static boolean isUserExists(String username) {
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_CONTAINS);
        usermatch.setMatchvalue(username);
        List<UserDataVOWS> result = null;
        try {
            result = mEjbcaraWs.findUser(usermatch);
        } catch (AuthorizationDeniedException_Exception | EjbcaException_Exception | EndEntityProfileNotFoundException_Exception | IllegalQueryException_Exception e) {

            return false;
        }
        return result.size() > 0;
    }

    public UserDataVOWS getUserByUserName(String username)
            throws AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            CertificateException, NoSuchAlgorithmException, KeyStoreException,
            NoSuchProviderException, IOException {

        UserMatch usermatch = new UserMatch();

        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(username);
        List<UserDataVOWS> result = null;

        try {
            result = mEjbcaraWs.findUser(usermatch);

            if (result.size() > 0) {
                UserDataVOWS user = result.get(0);
                return user;
            } else {
                return null;
            }
        } catch (AuthorizationDeniedException_Exception | EjbcaException_Exception | EndEntityProfileNotFoundException_Exception | IllegalQueryException_Exception e) {
            return null;
        }

    }

    public boolean AddUser(String name, String pass, String userDN, String CAname,
            String crtProfile, String eeProfile, String TokenType, String email) {

        try {
            if (isUserExists(name) == false) {
                UserDataVOWS user = new UserDataVOWS();
                if (!TokenType.equals("P12")) {
                    TokenType = UserDataVOWS.TOKEN_TYPE_USERGENERATED;
                }
                user.setUsername(name);
                user.setPassword(pass);
                user.setClearPwd(false);
                user.setSubjectDN(userDN);
                user.setCaName(CAname);
                user.setEmail(email);
                user.setEndEntityProfileName(eeProfile);
                user.setCertificateProfileName(crtProfile);
                user.setSubjectAltName(null);
                user.setStatus(10);
                user.setTokenType(TokenType);

                mEjbcaraWs.editUser(user);
                return true;
            } else {
                return true;
            }
        } catch (ApprovalException_Exception | AuthorizationDeniedException_Exception | CADoesntExistsException_Exception | EjbcaException_Exception | UserDoesntFullfillEndEntityProfile_Exception | WaitingForApprovalException_Exception ex) {

            return false;
        }

    }

    public boolean AddUser(UserDataVOWS user) {
        try {
            if (isUserExists(user.getUsername()) == false) {

                if (user.getTokenType().equals("P12")) {
                    user.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
                }
                mEjbcaraWs.editUser(user);
                return true;
            } else {
                return true;
            }
        } catch (ApprovalException_Exception | AuthorizationDeniedException_Exception | CADoesntExistsException_Exception | EjbcaException_Exception | UserDoesntFullfillEndEntityProfile_Exception | WaitingForApprovalException_Exception ex) {

            return false;
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
        mEjbcaraWs.revokeUser(name,
                RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, true);
        System.out.print("\n user :" + name + " is deleted !!");

    }

    public void revokeUser(String name)
            throws AlreadyRevokedException_Exception,
            ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception, WaitingForApprovalException_Exception {

        mEjbcaraWs.revokeUser(name,
                RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, false);
    }

    public void revokeCert(String issuerDN, String serialno, int reason_id)
            throws AlreadyRevokedException_Exception,
            ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, DateNotValidException_Exception,
            EjbcaException_Exception, NotFoundException_Exception,
            RevokeBackDateNotAllowedForProfileException_Exception,
            WaitingForApprovalException_Exception {
        mEjbcaraWs.revokeCert(issuerDN, serialno,
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
        mEjbcaraWs.revokeCert(issuerDN, serialno,
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
        mEjbcaraWs.revokeCert(issuerDN, serialno,
                RevokedCertInfo.NOT_REVOKED);

    }

    public byte[] GenP12file(String username, String keystorePassword, String keylength,
            String storePath) throws Exception {

        KeyStore ejbcaUserGeneratedKeystore = generateKeyStore(username, keystorePassword, keylength);
        java.security.KeyStore javaKeyStore = KeyStoreHelper.getKeyStore(ejbcaUserGeneratedKeystore.getKeystoreData(), "PKCS12", keystorePassword);
        InMemoryKeyStoreHolder inMemkeyStoreHolder = new InMemoryKeyStoreHolder(javaKeyStore);
        inMemkeyStoreHolder.init(keystorePassword);
        inMemkeyStoreHolder.storeToDrive(storePath);
        return null;
    }

    public byte[] generateCertificateFromCsr(String csrString, String username) throws Exception {

        UserMatch usermatch = new UserMatch();
        usermatch
                .setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch
                .setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(username);
        List<UserDataVOWS> userdatas = mEjbcaraWs.findUser(usermatch);
        // Set some user data
        final UserDataVOWS userData = userdatas.get(0);
        // Issue a certificate
        userData.setStatus(10);
        CertificateResponse response = mEjbcaraWs.certificateRequest(userData, csrString, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
        response.getCertificate();
   
        return response.getRawData();
    }

    public KeyStore generateKeyStore(String username, String keystorePassword, String keylength) throws Exception {

        UserMatch usermatch = new UserMatch();
        usermatch
                .setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch
                .setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(username);
        List<UserDataVOWS> userdatas = mEjbcaraWs.findUser(usermatch);

        if (userdatas != null) {
            userdatas.get(0).setStatus(10);
            userdatas.get(0).setTokenType("P12");
            mEjbcaraWs.editUser(userdatas.get(0));

            KeyStore ejbcaUserGeneratedKeystore = mEjbcaraWs.pkcs12Req(username, keystorePassword, null, keylength,
                    AlgorithmConstants.KEYALGORITHM_RSA);
            return ejbcaUserGeneratedKeystore;
        } else {
            return null;
        }
    }

    ;

    public void GenerateP12inHardwareToken(KeyStoreHolder keystoreHolder, String username,
            String cn, String keystorePassword, String keylength) throws Exception {
        KeyStore ejbcaUserGeneratedKeystore = generateKeyStore(username, keystorePassword, keylength);
        java.security.KeyStore javaKeyStore = KeyStoreHelper.getKeyStore(ejbcaUserGeneratedKeystore.getKeystoreData(), "PKCS12", keystorePassword);
        InMemoryKeyStoreHolder inMemkeyStoreHolder = new InMemoryKeyStoreHolder(javaKeyStore);
        inMemkeyStoreHolder.init(keystorePassword);
        PrivateKey privateKey = inMemkeyStoreHolder.getPrivateKey(cn);
        java.security.cert.Certificate[] chain = inMemkeyStoreHolder.getPrivateKeyChain(cn);
        keystoreHolder.importKeyPair(cn, privateKey, chain);
    }

    public CertificateStatus checkCertificateStatus(String username) {

        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_CONTAINS);
        usermatch.setMatchvalue(username);
        List<UserDataVOWS> result = null;
        try {
            result = mEjbcaraWs.findUser(usermatch);
            return checkCertificateStatus(result.get(0).getCaName(), result.get(0)
                    .getCertificateSerialNumber().toString());
        } catch (AuthorizationDeniedException_Exception | EjbcaException_Exception | EndEntityProfileNotFoundException_Exception | IllegalQueryException_Exception e) {
            // TODO Auto-generated catch block
            return CertificateStatus.UNKNOWN;
        }

    }

    public CertificateStatus checkCertificateStatus(String issuerDN, String certificateSerialno) {
        RevokeStatus revokestatus = null;
        try {
            revokestatus = mEjbcaraWs.checkRevokationStatus(issuerDN,
                    certificateSerialno);
            if (revokestatus != null) {

                if (revokestatus.getReason() == RevokeStatus.REVOKATION_REASON_CERTIFICATEHOLD) {// Certificate isn't revoked
                    return CertificateStatus.SUSPENDED;
                }
                if (revokestatus.getReason() == RevokeStatus.NOT_REVOKED) {
                    return CertificateStatus.ACTIVE;
                } else {
                    return CertificateStatus.REVOKED;
                }
            } else {
                return CertificateStatus.UNKNOWN;
            }
        } catch (AuthorizationDeniedException_Exception | CADoesntExistsException_Exception | EjbcaException_Exception e) {
            // TODO Auto-generated catch block
            return CertificateStatus.UNKNOWN;
        }

    }

    public UserStatus checkUserStatus(String username) {
        UserMatch usermatch = new UserMatch();
        usermatch
                .setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch
                .setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(username);
        List<UserDataVOWS> userdatas = null;
        try {
            userdatas = mEjbcaraWs.findUser(usermatch);

            if (userdatas.size() > 0) {
                switch (userdatas.get(0).getStatus()) {
                    case 10:
                        return UserStatus.NEW;
                    case 50:
                        return UserStatus.REVOKED;
                    case 40:
                        return UserStatus.GENERATED;

                    default:
                        return UserStatus.UNKNOWN;
                }
            } else {
                return UserStatus.NOT_FOUND;
            }

        } catch (AuthorizationDeniedException_Exception | EjbcaException_Exception | EndEntityProfileNotFoundException_Exception | IllegalQueryException_Exception e) {
            // TODO Auto-generated catch block

            return UserStatus.UNKNOWN;
        }

    }

    public String getUserlastCertAsAfile(String username) throws IOException {

        List<Certificate> certs = null;
        try {
            certs = mEjbcaraWs.findCerts(username, false);
            System.out.print(certs.size());
            if (certs.size() > 0) {
                String certificatePath = workingDirPath + username + ".crt";

                fileUtils.writeFile(certs.get(0).getCertificateData(), certificatePath);
                return certificatePath;
            } else {
                return null;
            }
        } catch (AuthorizationDeniedException_Exception | EjbcaException_Exception ex) {
            return null;
        }

    }

    public X509Certificate getUserX509Certificate(String username) {
        byte[] userlastcert = null;
        CertificateResponse CertResponse = null;
        X509Certificate usercert = null;
        List<Certificate> certs;
        try {
            certs = mEjbcaraWs.findCerts(username, false);
            int index = 0;
            userlastcert = certs.get(index)
                    .getRawCertificateData();

            CertResponse = new CertificateResponse(
                    CertificateHelper.RESPONSETYPE_CERTIFICATE, userlastcert);
            usercert = CertResponse.getCertificate();

            return usercert;
        } catch (AuthorizationDeniedException_Exception | EjbcaException_Exception | CertificateException e) {

            return usercert;
        }

    }

    public List<NameAndId> getEEprofiles() {
        try {
            return mEjbcaraWs.getAuthorizedEndEntityProfiles();
        } catch (AuthorizationDeniedException_Exception | EjbcaException_Exception e) {
            // TODO Auto-generated catch block
            return null;
        }

    }

    public List<NameAndId> getCertProfiles(int i) {
        try {
            return mEjbcaraWs.getAvailableCertificateProfiles(i);
        } catch (AuthorizationDeniedException_Exception | EjbcaException_Exception e) {
            return null;
        }
    }

    public List<NameAndId> getCAs() {
        try {
            return mEjbcaraWs.getAvailableCAs();

        } catch (AuthorizationDeniedException_Exception | EjbcaException_Exception e) {
            return null;
        }

    }
}
