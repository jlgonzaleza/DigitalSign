/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package co.softluciona.digitalsign.certificate;

import co.softluciona.digitalsign.certificate.verify.exception.VerifyCertificateException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.X509Extensions;

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
    private String ocspURL;
    private String crlURL;
    private static final String crl_oid = "2.5.29.31";
    public static final String crl_protocol = "http://";

    public CertificateInfo(X509Certificate certificateX509, PrivateKey privateKey, Certificate[] certificateChain, Provider provider) {
        this.certificateX509 = certificateX509;
        this.privateKey = privateKey;
        this.certificateChain = certificateChain;
        this.provider = provider;
        info = getOIDsAndValues(this.certificateX509.getSubjectDN().getName());
        infoIssuer = getOIDsAndValues(this.certificateX509.getIssuerDN().getName());
        this.ocspURL = loadOcspUrl(certificateX509);
        this.crlURL = loadCrlUrl(certificateX509);

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

    private String loadCrlUrl(X509Certificate certificate) {
        
        String crlDistributionPoints = new String(
                certificate.getExtensionValue(crl_oid));
        String[] crlDistributionPointsTokens = crlDistributionPoints
                .split(crl_protocol);
        boolean isdownload = false;
        for (int j = 0; j < crlDistributionPointsTokens.length; j++) {
            int indexCRL = crlDistributionPointsTokens[j]
                    .lastIndexOf(".crl");
            if (indexCRL != -1 && !isdownload) {
                return crl_protocol
                        + crlDistributionPointsTokens[j].substring(0,
                        indexCRL) + ".crl";
            }
        }
       
        return null;
    }

    /**
     * M�todo para obtener la URL del servidor OCSP
     *
     * @param certificate Certificado del que se quiere verificar el estado y
     * del que se obtendr� la direcci�n del servidor OCSP. Esta informaci�n se
     * encuentra en el campo Authority Info Access, con identificador
     * 1.3.6.1.5.5.7.1.1
     * @return URL del servidor OCSP
     * @throws OcspException Se lanza esta excepci�n en caso de generarse alg�n
     * error leyendo la informaci�n del certificado que se quiere verificar
     */
    private String loadOcspUrl(X509Certificate certificate) {
        ASN1Primitive obj;
        try {
            // Se obtiene el valor de la extensi�n correspondiente al Acceso a 
            // informaci�n de autoridad
            obj = getExtensionValue(certificate, X509Extensions.AuthorityInfoAccess.getId());
        } catch (IOException e) {
//            throw new VeifyCertificateException(VerifyCertificateException.getMessage("oscp.url.error"), e);
            return null;
        }
        if (obj == null) {
//            throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.read.data.error"));
            return null;
        }

        // Se recorren los valores que contienen el DER obtenido
        ASN1Sequence AccessDescriptions = (ASN1Sequence) obj;
        for (int i = 0; i < AccessDescriptions.size(); i++) {
            ASN1Sequence AccessDescription =
                    (ASN1Sequence) AccessDescriptions.getObjectAt(i);
            if (AccessDescription.size() != 2) {
//               throw new Vereturn null;rifyCertificateException(VerifyCertificateException.getMessage("oscp.read.data.error"));
                return null;
            } else {

                // Una vez se llega al valor que tiene la URL del servidor OCSP, 
                // se obtiene la cadena de caracteres del objeto DER y se retorna
                String AccessLocation = getStringFromGeneralName(
                        (ASN1Primitive) AccessDescription.getObjectAt(1));
                if (AccessLocation == null) {
//                    throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.read.data.error"));
                    return null;
                } else {
                    return AccessLocation;
                }
            }
        }

        return null;
    }

    /**
     * M�todo para obtener un String a partir de un objeto DER (Distinguished
     * Encoded Rules)
     *
     * @param names Objeto DER donde se almacena la cadena de caracteres a
     * obtener
     * @return String con la informaci�n que se obtuvo del DER proporcionado
     */
    private String getStringFromGeneralName(ASN1Primitive names) {
        DERTaggedObject taggedObject = (DERTaggedObject) names;
        return new String(ASN1OctetString.getInstance(taggedObject, false).getOctets());
    }

    /**
     * M�todo para obtener un objeto DER (Distinguished Encoded Rules) que se
     * encuentra en un certificado, dado su OID
     *
     * @param cert Certificado en el que se encuentra el objeto DER que se
     * quiere obtener
     * @param oid OID (Object Identifier Registry) que identifica el objeto que
     * se quiere obtener del certificado
     * @return	DERObject con la informaci�n del campo que se desea obtener.
     * @throws IOException Se lanza esta excepci�n en caso de haber alg�n
     * inconveniente leyendo el archivo del certificado
     */
    private ASN1Primitive getExtensionValue(X509Certificate cert, String oid)
            throws IOException {
        byte[] bytes = cert.getExtensionValue(oid);
        if (bytes == null) {
            return null;
        }
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        return aIn.readObject();
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

    /**
     * @return the ocspURL
     */
    public String getOcspURL() {
        return ocspURL;
    }

    /**
     * @return the crlURL
     */
    public String getCrlURL() {
        return crlURL;
    }
}
