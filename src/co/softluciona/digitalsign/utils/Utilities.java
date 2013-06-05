/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package co.softluciona.digitalsign.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 *
 * @author user
 */
public class Utilities {

    public static byte[] getBytesFromFile(String path) throws Exception,
            IOException {
        File file2process = new File(path);
        InputStream is = new FileInputStream(file2process);

        // Get the size of the file
        long length = file2process.length();

        // You cannot create an array using a long type.
        // It needs to be an int type.
        // Before converting to an int type, check
        // to ensure that file is not larger than Integer.MAX_VALUE.
        if (length > Integer.MAX_VALUE) {
            throw new Exception("File too long. ");
        }

        // Create the byte array to hold the data
        byte[] bytes = new byte[(int) length];

        // Read in the bytes
        int offset = 0;
        int numRead = 0;

        while (offset < bytes.length
                && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
            offset += numRead;
        }

        // Ensure all the bytes have been read in
        if (offset < bytes.length) {
            throw new Exception("Could not completely read file " + path);
        }

        // Close the input stream and return bytes
        is.close();

        return bytes;
    }

    public static String formatDate(Date date) {
        String patron = "dd/MM/yyyy HH:mm:ss";
        DateFormat df = new SimpleDateFormat(patron);
        return df.format(date) + " H";
    }
}
