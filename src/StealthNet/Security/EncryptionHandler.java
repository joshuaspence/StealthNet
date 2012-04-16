/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie and Stephen Gould
 *
 * PACKAGE:         StealthNet.Securtity
 * FILENAME:        EncryptionHandler.java
 * AUTHORS:         Joshua Spence and Ahmad Al Mutawa
 * DESCRIPTION:     An interface to provide encryption and decryption of 
 * 					communications to StealthNet.
 * VERSION:         1.0
 *
 *****************************************************************************/

package StealthNet.Security;

/* Import Libraries **********************************************************/

import java.io.UnsupportedEncodingException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

/* EncryptionHandler Interface Definition ************************************/

/**
 * An interface to provide encryption and decryption of messages, in order to 
 * provide confidentiality of the communications.
 * 
 * Ideally, only the sender should be able to encrypt the message; and only the
 * receiver should be able to decrypt the message.
 * 
 * @author Joshua Spence
 */
public interface EncryptionHandler {
	/**
	 * Encrypts a message using the encryption key.
	 * 
	 * @param cleartext The message to encrypt.
	 * @return The encrypted message.
	 * 
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException 
	 */
	public String encrypt(String cleartext) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException;
	
	/**
	 * Decrypts a message.
	 * 
	 * @param ciphertext The message to be decrypted.
	 * @return The cleartext message.
	 * 
	 * @throws UnsupportedEncodingException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public String decrypt(String ciphertext) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException;
}

/******************************************************************************
 * END OF FILE:     EncryptionHandler.java
 *****************************************************************************/