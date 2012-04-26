/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie, Stephen Gould and Ryan Junee
 *
 * PACKAGE:         StealthNet
 * FILENAME:        DecryptedPacket.java
 * AUTHORS:         Matt Barrie, Stephen Gould, Ryan Junee and Joshua Spence
 * DESCRIPTION:     Implementation of a StealthNet file. This class represents
 * 					encrypted file contents.
 *
 *****************************************************************************/

package StealthNet;

/* Import Libraries **********************************************************/

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.management.InvalidAttributeValueException;

import StealthNet.Security.Encryption;
import StealthNet.Security.HashedMessageAuthenticationCode;
import StealthNet.Security.MessageAuthenticationCode;
import StealthNet.Security.NonceGenerator;

/* StealthNet.EncryptedFile Class Definition *********************************/

/**
 * TODO
 * @author Joshua Spence
 */
public class EncryptedFile extends File {
	private static final long serialVersionUID = 1L;
	
	/** File contents. */
	byte[] salt;						/** The salt to use for decryption of the file. */
	final int saltBytes;				/** The number of bytes for the salt. */
	byte[] passwordHash;				/** A hash of the password for password verification. */
	final int passwordHashBytes;		/** The number of bytes for the password hash. */
    byte[] data;						/** The data contained in the file. */
    byte[] digest;						/** The MAC used to provide a message digest. */
    final int digestBytes;				/** The number of bytes for the digest. */

    /** 
     * TODO
     * @throws IOException 
     */
    public EncryptedFile(File parent, String child, int saltBytes, int passwordHashBytes, int digestBytes, MessageAuthenticationCode mac) throws IOException {
        super(parent, child);
        
        this.saltBytes = saltBytes;
        this.passwordHashBytes = passwordHashBytes;
        this.digestBytes = digestBytes;
        
        parseFile(this);
        
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
     * TODO
     * @throws IOException 
     */
    public EncryptedFile(String pathname, int saltBytes, int passwordHashBytes, int digestBytes) throws IOException {
        super(pathname);
        
        this.saltBytes = saltBytes;
        this.passwordHashBytes = passwordHashBytes;
        this.digestBytes = digestBytes;
        
        parseFile(this);
    }
    
    /** 
     * TODO
     * @throws IOException 
     */
    public EncryptedFile(String parent, String child, int saltBytes, int passwordHashBytes, int digestBytes) throws IOException {
        super(parent, child);
        
        this.saltBytes = saltBytes;
        this.passwordHashBytes = passwordHashBytes;
        this.digestBytes = digestBytes;
        
        parseFile(this);
    }
    
    /** 
     * TODO
     * @throws IOException 
     */
    public EncryptedFile(URI uri, int saltBytes, int passwordHashBytes, int digestBytes) throws IOException {
        super(uri);
        
        this.saltBytes = saltBytes;
        this.passwordHashBytes = passwordHashBytes;
        this.digestBytes = digestBytes;
        
        parseFile(this);
    }
    
    /**
     * TODO
     * @param file
     * @throws IOException
     */
    private void parseFile(File file) throws IOException {
    	final FileInputStream fileInputStream = new FileInputStream(file);
    	
    	/** Read the salt. */
    	salt = new byte[saltBytes];
    	fileInputStream.read(salt);
    	
    	/** Read the password hash. */
    	passwordHash = new byte[passwordHashBytes];
    	fileInputStream.read(passwordHash);
    	
    	/** Read the data. */
    	final long dataSize = file.length() - (saltBytes + passwordHashBytes + digestBytes);
    	data = new byte[(int) dataSize];
    	fileInputStream.read(data);
    	
    	/** Read the digest. */
    	digest = new byte[digestBytes];
    }
    
    /**
     * Decrypt this file.
     * 
     * @param d The encryption instance to decrypt the file. If null, then it
     * will be assumed that the file is not encrypted.
     * @return The decrypted file. If parameter d is null, then the  
     * DecryptedFile is identical to the data stored in the EncryptedPacket.
     * 
     * @throws BadPaddingException 
     * @throws IllegalBlockSizeException 
     * @throws UnsupportedEncodingException 
     */
    public DecryptedPacket decrypt(Encryption d) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
    	if (d != null) {
	    	final byte[] decryptedData = d.decrypt(data).getBytes();
	    	return new DecryptedFile(new String(decryptedData));
    	} else {
    		return new DecryptedFile(new String(data));
    	}
    }
}

/******************************************************************************
 * END OF FILE:     EncryptedFile.java
 *****************************************************************************/