/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package co.softluciona.digitalsign.exception;

/**
 *
 * @author user
 */
public abstract class DigitalSignException extends Exception {
    
    
    
    
    
    
    
    public DigitalSignException(String message){
        super(message);        
        
        
    }
    
    public DigitalSignException(String message,Exception e){
        super(e);
    }
}
