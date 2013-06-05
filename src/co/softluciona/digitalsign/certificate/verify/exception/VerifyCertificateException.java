/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package co.softluciona.digitalsign.certificate.verify.exception;

import co.softluciona.digitalsign.exception.DigitalSignException;
import java.util.ResourceBundle;

/**
 *
 * @author user
 */
public class VerifyCertificateException extends DigitalSignException{
    private static ResourceBundle resourceBundle = ResourceBundle.getBundle( "co.softluciona.digitalsign.messages.verify" );
    
    public static String getMessage(String codeName){
       return  resourceBundle.getString(codeName);
    }
    
     public VerifyCertificateException(String message){
        super(message);        
        
        
    }
    
    public VerifyCertificateException(String message,Exception e){
        super(message,e);
    }
    
}
