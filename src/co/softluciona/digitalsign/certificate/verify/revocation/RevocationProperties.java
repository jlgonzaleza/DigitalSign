/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package co.softluciona.digitalsign.certificate.verify.revocation;

import co.softluciona.digitalsign.certificate.verify.exception.VerifyCertificateException;
import java.io.File;
import java.util.Calendar;
import java.util.GregorianCalendar;

/**
 *
 * @author user
 */
public class RevocationProperties {

    /**
     * @return the pathKeystore
     */
    public String getPathKeystore() {
        return pathKeystore;
    }

    /**
     * @param pathKeystore the pathKeystore to set
     */
    public void setPathKeystore(String pathKeystore) {
        this.pathKeystore = pathKeystore;
    }

    public enum RevocationType {
        CRL, OCSP
    }
    private RevocationType type;
    private String pathCrl;
    private String ocspServer;
    private Calendar dateToVerify;
    private String pathKeystore;
    
    public RevocationProperties(RevocationType type, String pathCrl, Calendar dateToVerify, String oscpServer,String pathKeystore) throws VerifyCertificateException {
        this.type = type;
        this.ocspServer = oscpServer;
        if (this.type.equals(RevocationType.CRL)) {

            if (pathCrl != null && !pathCrl.isEmpty()) {
                this.pathCrl = pathCrl;
                File f = new File(pathCrl);
                if (!f.exists()) {
                    throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.pathCrl"));
                }

            } else {
                throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.pathCrl"));
            }
        }
        
        if (pathKeystore != null && !pathKeystore.isEmpty()) {
                this.pathKeystore = pathKeystore;
                File f = new File(pathKeystore);
                if (!(f.exists() && f.isFile())) {
                    throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.keystore.valid"));
                }

            }

        if (dateToVerify == null) {
            this.dateToVerify = new GregorianCalendar();
        } else {
            this.dateToVerify = dateToVerify;
        }
    }

    /**
     * @return the ocspServer
     */
    public String getOcspServer() {
        return ocspServer;
    }

    /**
     * @param ocspServer the ocspServer to set
     */
    public void setOcspServer(String ocspServer) {
        this.ocspServer = ocspServer;
    }

    /**
     * @return the dateToVerify
     */
    public Calendar getDateToVerify() {
        return dateToVerify;
    }

    /**
     * @param dateToVerify the dateToVerify to set
     */
    public void setDateToVerify(Calendar dateToVerify) {
        this.dateToVerify = dateToVerify;
    }

    /**
     * @return the type
     */
    public RevocationType getType() {
        return type;
    }

    /**
     * @param type the type to set
     */
    public void setType(RevocationType type) {
        this.type = type;
    }

    /**
     * @return the pathCrl
     */
    public String getPathCrl() {
        return pathCrl;
    }

    /**
     * @param pathCrl the pathCrl to set
     */
    public void setPathCrl(String pathCrl) {
        this.pathCrl = pathCrl;
    }
}
