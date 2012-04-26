/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie, Stephen Gould and Ryan Junee
 *
 * PACKAGE:         StealthNet
 * FILENAME:        DecryptedPacket.java
 * AUTHORS:         Matt Barrie, Stephen Gould, Ryan Junee and Joshua Spence
 * DESCRIPTION:     Implementation of a StealthNet file. This class represents
 * 					decrypted file contents.
 *
 *****************************************************************************/

package StealthNet;

/* Import Libraries **********************************************************/

import java.io.UnsupportedEncodingException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.management.InvalidAttributeValueException;

import StealthNet.Security.Encryption;
import StealthNet.Security.HashedMessageAuthenticationCode;
import StealthNet.Security.MessageAuthenticationCode;
import StealthNet.Security.NonceGenerator;

/* StealthNet.DecryptedFile Class Definition *********************************/

/** 
 * TODO
 * @author Joshua Spence
 */
public class DecryptedFile {
	/** File contents. */
    final byte[] data;						/** The data stored in the file. */
    final MessageAuthenticationCode mac;	/** The MAC used to provide a message digest. */

    /** 
     * Constructor with no digest. Explicitly copies the data array contents.
     *
     * @param d The data to be stored in the file.
     */
    public DecryptedFile(byte[] d) {
        if (d == null)
        	this.data = new byte[0];
        else {
        	this.data = new byte[d.length];
        	System.arraycopy(d, 0, this.data, 0, d.length);
        }
        
        /** No MAC is available. */
        this.mac = null;
    }
    
    /** 
     * Constructor with digest. Explicitly copies the data array contents.
     *
     * @param dLen The length of the data array.
     * @param d The data to be stored in the file.
     * @param mac The MessageAuthenticationCode instance to provide a MAC 
     * digest.
     */
    public DecryptedFile(byte[] d, int dLen, MessageAuthenticationCode mac) {
        /** Copy the data. */
        if (d == null)
        	this.data = new byte[0];
        else {
        	this.data = new byte[dLen];
        	System.arraycopy(d, 0, this.data, 0, dLen);
        }
        
        this.mac = mac;
    }

    /** 
     * Constructor. This function must "undo" the effects of the toString() 
     * function, because this function converts the buffered data into a file 
     * when it is opened.
     * 
     * @param str A string consisting of the file contents.
     */
    public DecryptedFile(String str) {  
    	/** 
    	 * Add padding if necessary, to make the packet length an integer number
    	 * of bytes (each represented by 2 hexadecimal characters).
    	 */
    	if (str.length() % 2 == 1)
            str = "0" + str;
    	
        if (str.length() == 0) {
        	/** NULL packet. */
            this.data = new byte[0];
            this.mac = null;
        } else {
        	/** Current index of the string. */
        	int current = 0;
        	
        	/** Data length (4 bytes). */
            int dataLen = Utility.hexToInt(str.substring(current, current + (4 * Utility.HEX_PER_BYTE)));
        	current += (4 * Utility.HEX_PER_BYTE);
            
            /** Data (dataLen bytes). */
            this.data = new byte[dataLen];
            for (int i = 0; i < data.length; i++)
            	this.data[i] = (byte) (16 * Utility.singleHexToInt(str.charAt(current++)) + Utility.singleHexToInt(str.charAt(current++)));
            
            /** No MAC is available. */
    		this.mac = null;
        }
    }

    /** 
     * Converts the file to a string. This function must undo the effects of 
     * the DecryptedFile(String) constructor, because this function is used to
     * convert a file to a string for storing on the file system.
     * 
     * @return A string representing the contents of the packet.
     */
    public String toString() {
    	String str = "";
        int lowHalfByte, highHalfByte;

        /** Data length (4 bytes). */
        str += Utility.intToHex(data.length);
        
        /** Data (data.length/2 bytes). */
        for (int i = 0; i < data.length; i++) {
        	highHalfByte = (data[i] >= 0) ? data[i] : 256 + data[i];
        	lowHalfByte = highHalfByte & 0xF;
            highHalfByte /= Utility.HEXTABLE.length;
            str += Utility.HEXTABLE[highHalfByte];
            str += Utility.HEXTABLE[lowHalfByte];
        }
        
        /** Done. */
        return str;
    }
    
    /**
     * Encrypt this file.
     * 
     * @param e The encryption instance to encrypt the packet. If null, then the
     * packet will not be encrypted.
     * @return The encrypted packet.
     * 
     * @throws BadPaddingException 
     * @throws IllegalBlockSizeException 
     * @throws UnsupportedEncodingException 
     * @throws IllegalArgumentException 
     * @throws InvalidAttributeValueException 
     */
    public EncryptedPacket encrypt(Encryption e) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAttributeValueException, IllegalArgumentException {
    	if (e != null) {
	    	final byte[] encryptedData = e.encrypt(this.toString()).getBytes();
	    	return new EncryptedPacket(encryptedData, encryptedData.length, HashedMessageAuthenticationCode.DIGEST_BYTES, this.mac);
    	} else {
    		return new EncryptedPacket(this.toString().getBytes(), this.toString().getBytes().length, HashedMessageAuthenticationCode.DIGEST_BYTES, this.mac);
    	}
    }
}

/******************************************************************************
 * END OF FILE:     DecryptedPacket.java
 *****************************************************************************/