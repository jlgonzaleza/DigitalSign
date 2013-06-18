/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package co.softluciona.digitalsign.certificate.verify;

import co.softluciona.digitalsign.certificate.verify.exception.VerifyCertificateException;
import co.softluciona.digitalsign.certificate.CertificateInfo;
import co.softluciona.digitalsign.certificate.verify.revocation.RevocationProperties;
import co.softluciona.digitalsign.certificate.verify.revocation.RevocationProperties.RevocationType;
import co.softluciona.digitalsign.certificate.verify.revocation.crl.CrlVerify;
import co.softluciona.digitalsign.certificate.verify.revocation.ocsp.OcspClient;
import co.softluciona.digitalsign.certificate.verify.revocation.ocsp.OcspResponse;
import co.softluciona.digitalsign.certificate.verify.revocation.ocsp.OcspUtils;
import co.softluciona.digitalsign.utils.Utilities;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.List;

/**
 *
 * @author user
 */
public abstract class CertificateVerify {

    protected CertificateInfo certInfo;
    private RevocationProperties revocation;
    private KeyStore caKeystore;

    public CertificateVerify(RevocationProperties revocation) throws VerifyCertificateException {
        if (revocation == null) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.revocation"));
        } else {
            this.revocation = revocation;
        }
    }

    protected abstract void validate() throws VerifyCertificateException;

    public CertificateInfo getCertificateInfo(){
        return this.certInfo;
    }
    
    public final CertificateInfo getVerifyAllCertificate() throws VerifyCertificateException {
        verifyExpiredDate();
        X509Certificate issuer = verifyTrust();
        verifyRevocation(issuer);
        return certInfo;
    }
    
    public final X509Certificate verifyTrust() throws VerifyCertificateException{
       return loadCA(this.certInfo.getInfoIssuer().get("CN"));
    }
    
    public final void verifyRevocation(X509Certificate issuer) throws VerifyCertificateException{
        if (revocation.getType().equals(RevocationType.CRL)) {
            CrlVerify.verifyRevocation(this.certInfo.getCertificateX509(), revocation.getDateToVerify(), revocation.getPathCrl(), this.certInfo.getInfoIssuer().get("CN"));
        } else if (revocation.getType().equals(RevocationType.OCSP)) {
            ocspVerify(this.certInfo.getCertificateX509(),issuer);
        }
    }
    
    public final void verifyExpiredDate() throws VerifyCertificateException{
        verifyDate(this.certInfo.getCertificateX509(), revocation.getDateToVerify());
    }

    private void verifyDate(X509Certificate cert, Calendar calendar) throws VerifyCertificateException {
        if (cert.hasUnsupportedCriticalExtension()) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("unsupported.critical.extension"));
        }
        try {
            cert.checkValidity(calendar.getTime());
        } catch (Exception e) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("certificate.expired") + Utilities.formatDate(calendar.getTime()));
        }
    }

    private X509Certificate loadCA(String commonName) throws VerifyCertificateException {


        try {
            caKeystore = loadCacertsKeyStore(revocation.getPathKeystore());
            Enumeration<String> localEnumeration = caKeystore.aliases();
            while (localEnumeration.hasMoreElements()) {
                String str = (String) localEnumeration.nextElement();
                if (caKeystore.isCertificateEntry(str)) {
                    Certificate localCertificate = caKeystore.getCertificate(str);
                    if (localCertificate instanceof X509Certificate) {
                        String[] array = ((X509Certificate) localCertificate).getSubjectDN().getName().split(",");
                        for (int j = 0; j < array.length; j++) {
                            if (array[j].trim().startsWith("CN=")) {

                                if (array[j].substring(3).trim().equals(commonName)) {

                                    return (X509Certificate) localCertificate;
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("keystore.read") + e.getMessage());
        }

        //No coincide las CA locales con el certificado
        throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.trust.certificate"));
    }

    private void ocspVerify(X509Certificate cert, X509Certificate issuer) throws VerifyCertificateException {
        OcspClient ocspClient;
        String server = this.revocation.getOcspServer();
        if (server == null || server.isEmpty()) {
            server = certInfo.getOcspURL();

        }
//        if (this.certParams.getRevocationVerify().isOcspProxy()) {
//            try {
//                ocspClient = new OcspClient(cert, issuer, server, this.certParams.getRevocationVerify().getProxyOscp(), this.certParams.getRevocationVerify().getProxyOscpPort(), this.certParams.getRevocationVerify().getProxyOscpUser(), this.certParams.getRevocationVerify().getProxyOscpPassword());
//
//                OcspResponse resp = ocspClient.ocspRequest();
//                if (resp.isRevoke()) {
//                    if (resp.getRevokeDate().compareTo(this.certParams.getRevocationVerify().getCalendar().getTime()) < 0) {
//                        throw new VerifyCertificateException(formatDate(resp.getRevokeDate()), 7);
//                    }
//                } else if (resp.isUnknow()) {
//                    throw new VerifyCertificateException(resp.getMessage(), 19);
//                }
//            } catch (OcspException e) {
//                throw new VerifyCertificateException(e.getMessage(), 19);
//            }
//        } else {
        ocspClient = new OcspClient(cert, issuer, server);
        OcspResponse resp = ocspClient.ocspRequest();
        if (resp.isRevoke()) {
            if (resp.getRevokeDate().compareTo(this.revocation.getDateToVerify().getTime()) < 0) {
                throw new VerifyCertificateException(VerifyCertificateException.getMessage("certificate.annulled") + Utilities.formatDate(resp.getRevokeDate()));
            }
        } else if (resp.isUnknow()) {
            //esta entrando a es desconocido
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("ocsp.unknow.answer"));
        }

//        }
    }

    private KeyStore loadCacertsKeyStore(String keyStorePath) throws Exception {
        File file;
        FileInputStream fin = null;
        boolean propio = false;
        if (keyStorePath == null || keyStorePath.equals("")) {
            file = new File(System.getProperty("java.home") + "/lib/security/cacerts");
        } else {
            file = new File(keyStorePath);
            propio = true;
        }
        try {
            fin = new FileInputStream(file);
            KeyStore k;
            k = KeyStore.getInstance("JKS");
            if (!propio) {
                k.load(fin, "changeit".toCharArray());
            } else {
                k.load(fin, "willman".toCharArray());
            }
            return k;
        } catch (Exception e) {
            throw new Exception(e);
        } finally {
            try {
                if (fin != null) {
                    fin.close();
                }
            } catch (Exception ex) {
            }
        }
    }
}
