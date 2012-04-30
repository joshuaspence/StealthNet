/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie, Stephen Gould and Ryan Junee
 *
 * PACKAGE:         StealthNet
 * FILENAME:        EncryptedPacket.java
 * AUTHORS:         Matt Barrie, Stephen Gould, Ryan Junee and Joshua Spence
 * DESCRIPTION:     Implementation of a StealthNet packet. This class represents
 * 					encrypted packet contents.
 *
 *****************************************************************************/

package StealthNet;

/* Import Libraries **********************************************************/

import java.io.UnsupportedEncodingException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.management.InvalidAttributeValueException;

import StealthNet.Security.Encryption;
import StealthNet.Security.MessageAuthenticationCode;

/* StealthNet.Packet Class Definition ****************************************/

/**
 * A class to store the encrypted data passed between StealthNet clients. An 
 * encrypted StealthNet "packet" consists of two parts:
 *     - data (encrypted)
 *     - digest
 *  
 * A message digest is produced by passing a MessageAuthenticationCode instance
 * to the relevant function. This class  will allow encrypted packets to be 
 * created without a digest (if a null MessageAuthenticationCode instance is
 * passed to the function, for instance). A higher layer should check whether or
 * not this should be allowed.
 * 
 * The data contained in this class does not necessarily have to be encrypted, 
 * it could simply be the same data that was contained in the corresponding 
 * DecryptedPacket class. However, EncryptedPackets are the only packets that 
 * are transmitted over the communications channel.
 * 
 * @author Matt Barrie
 * @author Stephen Gould
 * @author Ryan Junee
 * @author Joshua Spence
 */
public class EncryptedPacket {
    /** Packet contents. */
    final byte data[];		/** The (encrypted) data being sent in the packet. */
    final byte digest[];	/** The MAC digest of the packet data (in base64 encoding). */

    /** 
     * Null constructor.
     * 
     * @param digestBytes The fixed size of the message digest.
     */
    public EncryptedPacket(int digestBytes) {
        /** No data is available. */
    	this.data = new byte[0];
        
        /** No digest is available. */
        this.digest = new byte[digestBytes];
    }
    
    /** 
     * Constructor with no digest. Explicitly copies the data array contents.
     *
     * @param encryptedData The (encrypted) data to be sent in the packet.
     * @param digestBytes The fixed size of the message digest.
     */
    public EncryptedPacket(byte[] encryptedData, int digestBytes) {
        if (encryptedData == null)
        	this.data = new byte[0];
        else {
        	this.data = new byte[encryptedData.length];
        	System.arraycopy(encryptedData, 0, this.data, 0, encryptedData.length);
        }
        
        /** No digest is available. */
        this.digest = new byte[digestBytes];
    }
    
    /** 
     * Constructor with digest. Explicitly copies the data array contents.
     *
     * @param encryptedDataLen The length of the encryptedData array.
     * @param encryptedData The data to be sent in the packet.
     * @param digestBytes The fixed size of the message digest.
     * @param mac The MessageAuthenticationCode instance to provide a MAC 
     * digest. If null, then the digest will be blank.
     * 
     * @throws IllegalArgumentException
     * @throws InvalidAttributeValueException 
     */
    public EncryptedPacket(byte[] encryptedData, int encryptedDataLen, int digestBytes, MessageAuthenticationCode mac) throws IllegalArgumentException, InvalidAttributeValueException {
        /** Copy the data. */
        if (encryptedData == null)
        	this.data = new byte[0];
        else  {
        	this.data = new byte[encryptedDataLen];
        	System.arraycopy(encryptedData, 0, this.data, 0, encryptedDataLen);
        }
        
        /** Create the MAC digest (if possible). */
        if (mac == null)
        	this.digest = new byte[digestBytes];
        else {
        	this.digest = mac.createMAC(this.data);
        	
        	if (this.digest.length != digestBytes)
        		throw new IllegalArgumentException("Specified digest size does not equal to actual digest size. Specified size: " + digestBytes + ". Actual size: " + this.digest.length + ".");
        }
    }

    /** 
     * Constructor. This function must "undo" the effects of the toString() 
     * function, because this function converts the received data into a packet
     * at the receiving end of communications.
     * 
     * @param str A string consisting of the packet contents.
     * @param digestBytes The fixed size of the message digest.
     */
    public EncryptedPacket(String str, int digestBytes) {  
    	/** 
    	 * Add padding if necessary, to make the packet length an integer number
    	 * of bytes (each represented by 2 hexadecimal characters).
    	 */
    	if (str.length() % 2 == 1)
            str = "0" + str;
    	
        if (str.length() == 0) {
        	/** NULL packet. */
            this.data = new byte[0];
            this.digest = new byte[0];
        } else {
        	/** Current index of the string. */
        	int current = 0;
        	
        	/** Data length. */
        	int dataLen = (str.length() / Utility.HEX_PER_BYTE) - digestBytes;
            
            /** Data (dataLen bytes). */
            this.data = new byte[dataLen];
            for (int i = 0; i < data.length; i++)
            	this.data[i] = (byte) (16 * Utility.singleHexToInt(str.charAt(current++)) + Utility.singleHexToInt(str.charAt(current++)));
            
            /** Digest (digestBytes bytes). */
            this.digest = new byte[digestBytes];
            for (int i = 0; i < digest.length; i++)
            	this.digest[i] = (byte) (16 * Utility.singleHexToInt(str.charAt(current++)) + Utility.singleHexToInt(str.charAt(current++)));
        }
    }

    /** 
     * Converts the packet to a string. This function must undo the effects of 
     * the StealthNet.EncryptedPacket(String) constructor, because this function
     * is used to convert a packet to a string for transmission at the sending 
     * end of communications.
     * 
     * @return A string representing the contents of the packet.
     */
    public String toString() {
        String str = "";
        int lowHalfByte, highHalfByte;
        
        /** Data (data.length bytes). */
        for (int i = 0; i < data.length; i++) {
        	highHalfByte = (data[i] >= 0) ? data[i] : (256 + data[i]);
        	lowHalfByte = highHalfByte & 0xF;
            highHalfByte /= Utility.HEXTABLE.length;
            str += Utility.HEXTABLE[highHalfByte];
            str += Utility.HEXTABLE[lowHalfByte];
        }
        
        /** Digest (digest.length bytes). */
        for (int i = 0; i < digest.length; i++) {
        	highHalfByte = (digest[i] >= 0) ? digest[i] : (256 + digest[i]);
        	lowHalfByte = highHalfByte & 0xF;
            highHalfByte /= Utility.HEXTABLE.length;
            str += Utility.HEXTABLE[highHalfByte];
            str += Utility.HEXTABLE[lowHalfByte];
        }

        return str;
    }
    
    /**
     * Verify a MAC digest by calculating our own MAC digest of the same data,
     * and comparing it with the MAC digest stored in the packet. If the 
     * MessageAuthenticationCode instance is null, then the verification will 
     * pass automatically. Beware that this may not always be the desired 
     * result, so this should be checked at a higher layer.
     * 
     * @param mac The MessageAuthenticationCode instance to calculate the MAC 
     * digest.
     * @return True if the digest matches (or if the MessageAuthenticationCode 
     * instance is null), otherwise false.
     * 
     * @throws InvalidAttributeValueException 
     */
    public boolean verifyMAC(MessageAuthenticationCode mac) throws InvalidAttributeValueException {
    	if (mac == null)
    		return true;
    	else
    		return mac.verifyMAC(data, digest);
    }
    
    /**
     * Get a string representation of the packet. For debug purposes only. 
     * 
     * @return A comma-separated string containing the the value of each of the
     * packet's fields. For purely cosmetic purposes, newline characters will be
     * replaced by semicolons.
     */
    public String getEncryptedString() {
    	String str = "";
    	
    	/** Packet data. */
    	if (data.length > 0)
    		str += (new String(data)).replaceAll("\n", ";");
    	else
    		str += "null";
    	str += ", ";
    	
    	/** Packet digest. */
    	if (digest.length > 0)
    		str += Utility.getHexValue(digest);
    	else
    		str += "null";
    	
    	return str;
    }
    
    /**
     * Decrypt this packet.
     * 
     * @param d The encryption instance to decrypt the packet. If null, then it
     * will be assumed that the packet is not encrypted.
     * @return The decrypted packet. If parameter d is null, then the 
     * DecryptedPacket is identical to the data stored in the EncryptedPacket.
     * 
     * @throws BadPaddingException 
     * @throws IllegalBlockSizeException 
     * @throws UnsupportedEncodingException 
     */
    public DecryptedPacket decrypt(Encryption d) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
    	if (d != null) {
	    	final byte[] decryptedData = d.decrypt(data);
	    	return new DecryptedPacket(new String(decryptedData));
    	} else {
    		return new DecryptedPacket(new String(data));
    	}
    }
}

/******************************************************************************
 * END OF FILE:     EncryptedPacket.java
 *****************************************************************************/