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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import StealthNet.Security.AESEncryption;
import StealthNet.Security.HashedMessageAuthenticationCode;
import StealthNet.Security.InvalidPasswordException;
import StealthNet.Security.MessageAuthenticationCode;
import StealthNet.Security.PasswordEncryption;

/* StealthNet.EncryptedFile Class Definition *********************************/

/**
 * TODO
 * @author Joshua Spence
 */
public class EncryptedFile {
	/** Debug options. */
	private static final boolean DEBUG_FILE_IO     = Debug.isDebug("StealthNet.EncryptedFile.FileIO");
	
	/** File contents. */
	private byte[] salt;						/** The salt to use for decryption of the file. */
	private byte[] passwordHash;				/** A hash of the password for password verification. */
	private byte[] data;						/** The data contained in the file. */
	private byte[] digest;						/** The MAC used to provide a message digest. */
    
    private String filename;					/** The name of the file. */
    private final String password;				/** The password to attempt to encrypt/decrypt the file. */
    private final PasswordEncryption encryption; /** The class to use to encrypt/decrypt the file. */
    //private final MessageAuthenticationCode mac;
    
    /** 
     * TODO
     * 
     * @throws IOException 
     * @throws NoSuchPaddingException 
     * @throws InvalidAlgorithmParameterException 
     * @throws InvalidKeySpecException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     */
    public EncryptedFile(File file, String password) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException {    	
    	/** Parse the file. */
    	final FileInputStream fileInputStream = new FileInputStream(file);
    	final BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
    	final DataInputStream dataInputStream = new DataInputStream(bufferedInputStream);
    	
    	/** Read the salt. */
    	final int saltBytes = dataInputStream.readInt();
    	this.salt = new byte[saltBytes];
    	dataInputStream.read(this.salt);
    	
    	/** Read the password hash. */
    	final int hashBytes = dataInputStream.readInt();
    	this.passwordHash = new byte[hashBytes];
    	dataInputStream.read(this.passwordHash);
    	
    	/** Read the data. */
    	final int dataBytes = dataInputStream.readInt();
    	this.data = new byte[dataBytes];
    	dataInputStream.read(this.data);
    	
    	/** Read the digest. */
    	final int digestBytes = dataInputStream.readInt();
    	this.digest = new byte[digestBytes];
    	dataInputStream.read(this.digest);
    	
    	this.filename = file.getName();
    	this.password = password;
    	this.encryption = new PasswordEncryption(this.salt, this.password);
    	//this.mac = new HashedMessageAuthenticationCode(this.encryption.getSecretKey());
    	
    	/** Clean up. */
    	dataInputStream.close();
    	bufferedInputStream.close();
    	fileInputStream.close();
    }
    
    /** 
     * TODO
     * @throws IOException 
     * @throws NoSuchPaddingException 
     * @throws InvalidAlgorithmParameterException 
     * @throws InvalidKeySpecException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     */
    public EncryptedFile(URL file, String password) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException {
    	/** Parse the file. */
    	final InputStream inputStream = file.openStream();
    	final BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
    	final DataInputStream dataInputStream = new DataInputStream(bufferedInputStream);
    	
    	/** Read the salt. */
    	final int saltBytes = dataInputStream.readInt();
    	this.salt = new byte[saltBytes];
    	dataInputStream.read(this.salt);
    	
    	/** Read the password hash. */
    	final int hashBytes = dataInputStream.readInt();
    	this.passwordHash = new byte[hashBytes];
    	dataInputStream.read(this.passwordHash);
    	
    	/** Read the data. */
    	final int dataBytes = dataInputStream.readInt();
    	this.data = new byte[dataBytes];
    	dataInputStream.read(this.data);
    	
    	/** Read the digest. */
    	final int digestBytes = dataInputStream.readInt();
    	this.digest = new byte[digestBytes];
    	dataInputStream.read(this.digest);
    	
    	this.filename = file.getFile();
    	this.password = password;
    	this.encryption = new PasswordEncryption(this.salt, this.password);
    	//this.mac = new HashedMessageAuthenticationCode(this.encryption.getSecretKey());
    	
    	/** Clean up. */
    	dataInputStream.close();
    	inputStream.close();
    }
    
    /** 
     * TODO
     * 
     * @throws IOException 
     * @throws NoSuchAlgorithmException 
     * @throws BadPaddingException 
     * @throws IllegalBlockSizeException 
     * @throws NoSuchPaddingException 
     * @throws InvalidAlgorithmParameterException 
     * @throws InvalidKeySpecException 
     * @throws InvalidKeyException 
     */
    public EncryptedFile(byte[] decryptedData, String password) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException {
    	this.filename = null;
    	this.password = password;
    	this.encryption = new PasswordEncryption(this.password);
    	//this.mac = new HashedMessageAuthenticationCode(this.encryption.getSecretKey());
    	
    	this.salt = this.encryption.getSalt();
    	this.data = this.encryption.encrypt(decryptedData);
    	
    	/** Generate the message digest. */
    	//this.digest = new byte[HashedMessageAuthenticationCode.DIGEST_BYTES];
    	this.digest = new byte[0];
    	//this.digest = mac.createMAC(data);
    	
    	/** Generate the password hash. */
    	final MessageDigest mdb = MessageDigest.getInstance(AESEncryption.HASH_ALGORITHM);
    	this.passwordHash = mdb.digest(this.password.getBytes());
    }
    
    /**
     * TODO
     * 
     * @param output
     * 
     * @throws IOException
     */
    public void writeToFile(File output) throws IOException {
    	filename = output.getName();
    	final FileOutputStream fileOutputStream = new FileOutputStream(output);
    	final BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream);
		final DataOutputStream dataOutputStream = new DataOutputStream(bufferedOutputStream);
		
		if (DEBUG_FILE_IO) System.out.println("Writing encrypted data to file '" + filename + "' with password '" + password + "'.");
		
    	/** Write the salt to the file. */
		dataOutputStream.writeInt(salt.length);
		dataOutputStream.write(salt);

		/** Write the password hash to file. */
		dataOutputStream.writeInt(passwordHash.length);
		dataOutputStream.write(passwordHash);
		
		/** Write the (encrypted) data to file. */
		dataOutputStream.writeInt(data.length);
		dataOutputStream.write(data);
		
		/** Write the digest to file. */
		dataOutputStream.writeInt(digest.length);
		dataOutputStream.write(digest);
		
		/** Clean up. */
		dataOutputStream.flush();
		bufferedOutputStream.flush();
		fileOutputStream.flush();
		dataOutputStream.close();
		bufferedOutputStream.close();
		fileOutputStream.close();
    }
    
    /**
     * Decrypt this file.
     * 
     * TODO
     * 
     * @throws BadPaddingException 
     * @throws IllegalBlockSizeException 
     * @throws UnsupportedEncodingException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidPasswordException 
     */
    public byte[] decrypt() throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidPasswordException {
    	if (DEBUG_FILE_IO) System.out.println("Decrypting '" + filename + "' with password: " + password);
    	
    	/** Check the password. */
    	final MessageDigest mdb = MessageDigest.getInstance(AESEncryption.HASH_ALGORITHM);
    	final byte[] ourPasswordHash = mdb.digest(password.getBytes());
    	if (!Arrays.equals(passwordHash, ourPasswordHash))
    		throw new InvalidPasswordException("Invalid password to decrypt file.");
    	
    	/** Check the digest. */
    	//if (!mac.verifyMAC(data, digest)) {
    		
    	//}
    	
    	if (encryption != null) {
	    	return encryption.decrypt(data);
    	} else {
    		return data;
    	}
    }
}

/******************************************************************************
 * END OF FILE:     EncryptedFile.java
 *****************************************************************************/