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
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws IllegalStateException
	 */
	public byte[] encrypt(String cleartext) throws IllegalBlockSizeException, BadPaddingException, IllegalStateException;
	
	/**
	 * Encrypts a message using the encryption key.
	 * 
	 * @param cleartext The message to encrypt.
	 * @return The encrypted message.
	 * 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws IllegalStateException
	 */
	public byte[] encrypt(byte[] cleartext) throws IllegalBlockSizeException, BadPaddingException, IllegalStateException;
	
	/**
	 * Decrypts a message using the decryption key.
	 * 
	 * @param ciphertext The message to be decrypted.
	 * @return The cleartext message.
	 * 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public byte[] decrypt(String ciphertext) throws IllegalBlockSizeException, BadPaddingException;
	
	/**
	 * Decrypts a message using the decryption key.
	 * 
	 * @param ciphertext The message to be decrypted.
	 * @return The cleartext message.
	 * 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public byte[] decrypt(byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException;
}

/******************************************************************************
 * END OF FILE:     Encryption.java
 *****************************************************************************/