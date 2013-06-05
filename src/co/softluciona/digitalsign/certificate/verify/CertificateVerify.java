/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package co.softluciona.digitalsign.certificate.verify;

import co.softluciona.digitalsign.certificate.CertificateInfo;
import co.softluciona.digitalsign.certificate.verify.revocation.RevocationProperties;
import co.softluciona.digitalsign.certificate.verify.revocation.RevocationProperties.RevocationType;
import co.softluciona.digitalsign.exception.DigitalSignException;
import co.softluciona.digitalsign.utils.Utilities;
import java.security.cert.X509Certificate;
import java.util.Calendar;

/**
 *
 * @author user
 */
public abstract class CertificateVerify {

    protected CertificateInfo certInfo;
    private RevocationProperties revocation;

    public CertificateVerify(RevocationProperties revocation) throws VerifyCertificateException {
        if (revocation == null) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.revocation"));
        } else {
            this.revocation = revocation;
        }
    }

    public abstract void validate() throws VerifyCertificateException;

    public CertificateInfo getCertificate() throws VerifyCertificateException {
        verifyDate(this.certInfo.getCertificateX509(),revocation.getDateToVerify());
        if(revocation.getType().equals(RevocationType.CRL)){
            
        }else if(revocation.getType().equals(RevocationType.OCSP)){
            
        }
        return certInfo;
    }

    private void verifyDate(X509Certificate cert, Calendar calendar) throws VerifyCertificateException {
        if (cert.hasUnsupportedCriticalExtension()) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("unsupported.critical.extension"));
        }
        try {
            cert.checkValidity(calendar.getTime());
        } catch (Exception e) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("certificate.expired") + " " + Utilities.formatDate(calendar.getTime()));
        }
    }
}
