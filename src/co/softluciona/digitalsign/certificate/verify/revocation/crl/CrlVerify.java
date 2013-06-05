/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package co.softluciona.digitalsign.certificate.verify.revocation.crl;

import co.softluciona.digitalsign.certificate.verify.VerifyCertificateException;
import co.softluciona.digitalsign.exception.DigitalSignException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Calendar;

/**
 *
 * @author user
 */
public class CrlVerify {

    public static final String CRL_EXT = ".crl";
    private String pathCrl;

    public X509CRL loadCrl(String commonName) throws DigitalSignException {
        File crlFile = new File(pathCrl);
        File[] crls;
        if (pathCrl.endsWith(CRL_EXT)) {
            File[] crlsFiles = {crlFile};
            crls = crlsFiles;
        } else {
            crls = crlFile.listFiles();
        }

        if (crls == null || crls.length == 0) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.crl.files.found") + " " + pathCrl);
        }

        for (File crl : crls) {
            if (crl.isFile()) {
                FileInputStream fis;
                try {
                    fis = new FileInputStream(crl);
                } catch (FileNotFoundException ex) {
                    throw new VerifyCertificateException(VerifyCertificateException.getMessage("file.not.found") + " " + crl.getAbsolutePath());
                }
                // CRL creation
                X509CRL crlAux = null;
                try {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    crlAux = (X509CRL) cf.generateCRL(fis);
                    String key = "";
                    String[] CRLIssuerDN = crlAux.getIssuerDN().getName()
                            .split(",");
                    for (int j = 0; j < CRLIssuerDN.length; j++) {
                        if (CRLIssuerDN[j].trim().startsWith("CN=")) {
                            key = CRLIssuerDN[j].substring(3).trim();
                            if (key.equals(commonName)) {
                                return crlAux;
                            }
                        }
                    }
                    fis.close();
                } catch (Exception e) {
                }
            }
        }
        throw new VerifyCertificateException(VerifyCertificateException.getMessage("crl.not.found"));
    }

    private void verifyCrlExpireDate(X509CRL crl, Calendar calendar) throws DigitalSignException {
        if (crl.getNextUpdate().compareTo(calendar.getTime()) <= 0) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("crl.expired"));
        }
    }

    private void verifyCertificateAgainsCrl(X509CRL crl, X509Certificate cert, Calendar calendar) throws VerifyCertificateException {
       
            X509CRLEntry crlentry = crl.getRevokedCertificate(cert);
            if (crlentry != null && calendar.getTime().after(crlentry.getRevocationDate())) {
                throw new VerifyCertificateException(VerifyCertificateException.getMessage("certificate.annulled"));
            }
    }
}
