/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Securtity
 * FILENAME:        Encryption.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     An interface to provide the encryption and decryption of 
 * 					packets in StealthNet.
 *
 *****************************************************************************/

package StealthNet.Security;

/* Import Libraries **********************************************************/

import java.io.UnsupportedEncodingException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

/* StealthNet.Security.Encryption Interface Definition ***********************/

/**
 * An interface to provide encryption and decryption of messages, in order to 
 * provide confidentiality of the communications in StealthNet.
 * 
 * Ideally, only the sender should be able to encrypt the message; and only the
 * receiver should be able to decrypt the message.
 * 
 * @author Joshua Spence
 */
public interface Encryption {
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
	 * Encrypts a message using the encryption key.
	 * 
	 * @param cleartext The message to encrypt.
	 * @return The encrypted message.
	 * 
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException 
	 */
	public String encrypt(byte[] cleartext) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException;
	
	/**
	 * Decrypts a message using the decryption key.
	 * 
	 * @param ciphertext The message to be decrypted.
	 * @return The cleartext message.
	 * 
	 * @throws UnsupportedEncodingException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public String decrypt(String ciphertext) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException;
	
	/**
	 * Decrypts a message using the decryption key.
	 * 
	 * @param ciphertext The message to be decrypted.
	 * @return The cleartext message.
	 * 
	 * @throws UnsupportedEncodingException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public String decrypt(byte[] ciphertext) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException;
}

/******************************************************************************
 * END OF FILE:     Encryption.java
 *****************************************************************************/