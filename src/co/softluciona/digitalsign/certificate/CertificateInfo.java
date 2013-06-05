/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package co.softluciona.digitalsign.certificate;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;

/**
 *
 * @author user
 */
public class CertificateInfo {

    private X509Certificate certificateX509;
    private Certificate[] certificateChain;
    private PrivateKey privateKey;
    private Provider provider;
    private HashMap<String, String> info;
    private HashMap<String, String> infoIssuer;

    public CertificateInfo(X509Certificate certificateX509,PrivateKey privateKey,Certificate[] certificateChain,Provider provider) {
        this.certificateX509 = certificateX509;
        this.privateKey = privateKey;
        this.certificateChain = certificateChain;
        this.provider = provider;
        info = getOIDsAndValues(this.certificateX509.getSubjectDN().getName());
        infoIssuer = getOIDsAndValues(this.certificateX509.getIssuerDN().getName());
    }

    private HashMap<String, String> getOIDsAndValues(String distinguishedName) {
        HashMap<String, String> info_ = new HashMap<String, String>();
        String[] stringArray = distinguishedName.split(",");
        String[] stringArrayTemp;

        for (int i = 0; i < stringArray.length; i++) {
            stringArrayTemp = stringArray[i].split("=");
            if (stringArrayTemp.length == 2) {
                info_.put(stringArrayTemp[0].toString(), stringArrayTemp[1].toString().trim());
            }
        }
        return info_;
    }

    /**
     * @return the certificateX509
     */
    public X509Certificate getCertificateX509() {
        return certificateX509;
    }
    /**
     * @return the info
     */
    public HashMap<String, String> getInfo() {
        return info;
    }

    /**
     * @return the infoIssuer
     */
    public HashMap<String, String> getInfoIssuer() {
        return infoIssuer;
    }

    /**
     * @return the certificateChain
     */
    public Certificate[] getCertificateChain() {
        return certificateChain;
    }

    /**
     * @return the privateKey
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

  /**
     * @return the provider
     */
    public Provider getProvider() {
        return provider;
    }

}
