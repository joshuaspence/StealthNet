/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Securtity
 * FILENAME:        Encryption.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     A base class to provide the encryption and decryption of
 * 					packets in StealthNet.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet.Security;

/* Import Libraries ******************************************************** */

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

/* StealthNet.Security.Encryption Class Definition ************************ */

/**
 * A base class to provide encryption and decryption of messages, in order to
 * provide confidentiality of the communications in StealthNet. <p> Ideally,
 * only the sender should be able to encrypt the message; and only the receiver
 * should be able to decrypt the message.
 * 
 * @author Joshua Spence
 */
public class Encryption {
	/** The {@link Key} used to encrypt data. */
	protected Key encryptionKey;
	
	/** The {@link Cipher} used to encrypt data. */
	protected Cipher encryptionCipher;
	
	/** The {@link Key} used to decrypt data. */
	protected Key decryptionKey;
	
	/** The {@link Cipher} used to decrypt data. */
	protected Cipher decryptionCipher;
	
	/** The algorithm used to initialise the {@link Cipher}s. */
	private final String algorithm;
	
	/**
	 * Constructor.
	 * 
	 * @param algorithm The {@link Cipher} algorithm to be used for encryption
	 *        and decryption.
	 */
	protected Encryption(final String algorithm) {
		this.algorithm = algorithm;
	}
	
	/**
	 * Set the encryption {@link Cipher} and {@link Key}. <p> These must be set
	 * before attempting to encrypt any data.
	 * 
	 * @param key The {@link Key} to be used for encryption.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	protected final void setEncryption(final Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		encryptionKey = key;
		encryptionCipher = Cipher.getInstance(algorithm);
		encryptionCipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
	}
	
	/**
	 * Set the encryption {@link Cipher} and {@link Key}. <p> These must be set
	 * before attempting to encrypt any data.
	 * 
	 * @param key The {@link Key} to be used for encryption.
	 * @param specs The {@link AlgorithmParameterSpec} to be used for the
	 *        {@link Cipher}.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 */
	protected final void setEncryption(final Key key, final AlgorithmParameterSpec specs) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		encryptionKey = key;
		encryptionCipher = Cipher.getInstance(algorithm);
		encryptionCipher.init(Cipher.ENCRYPT_MODE, encryptionKey, specs);
	}
	
	/**
	 * Set the decryption {@link Cipher} and {@link Key}. <p> These must be set
	 * before attempting to decrypt any data.
	 * 
	 * @param key The {@link Key} to be used for decryption.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	protected final void setDecryption(final Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		decryptionKey = key;
		decryptionCipher = Cipher.getInstance(algorithm);
		decryptionCipher.init(Cipher.DECRYPT_MODE, decryptionKey);
	}
	
	/**
	 * Set the decryption {@link Cipher} and {@link Key}. <p> These must be set
	 * before attempting to decrypt any data.
	 * 
	 * @param key The {@link Key} to be used for encryption.
	 * @param specs The {@link AlgorithmParameterSpec} to be used for the
	 *        {@link Cipher}.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 */
	protected final void setDecryption(final Key key, final AlgorithmParameterSpec specs) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		decryptionKey = key;
		decryptionCipher = Cipher.getInstance(algorithm);
		decryptionCipher.init(Cipher.DECRYPT_MODE, decryptionKey, specs);
	}
	
	/**
	 * Encrypts data using the encryption key. Performs the opposite of the
	 * <code>decrypt(String)</code> function.
	 * 
	 * @param cleartext The data to encrypt.
	 * @return The encrypted message, encoded in base-64.
	 * 
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IllegalStateException If the encryption cipher hasn't been set.
	 * @see Base64
	 */
	public byte[] encrypt(final String cleartext) throws IllegalBlockSizeException, BadPaddingException {
		if (encryptionCipher == null)
			throw new IllegalStateException("Cannot perform encryption without an encryption cipher.");
		
		return encrypt(cleartext.getBytes());
	}
	
	/**
	 * Encrypts data using the encryption key. Performs the opposite of the
	 * <code>decrypt(byte[])</code> function.
	 * 
	 * @param cleartext The data to encrypt.
	 * @return The encrypted message, encoded in base-64.
	 * 
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IllegalStateException If the encryption cipher hasn't been set.
	 * @see Base64
	 */
	public byte[] encrypt(final byte[] cleartext) throws IllegalBlockSizeException, BadPaddingException {
		if (encryptionCipher == null)
			throw new IllegalStateException("Cannot perform encryption without an encryption cipher.");
		
		final byte[] encryptedValue = encryptionCipher.doFinal(cleartext);
		final byte[] encodedValue = Base64.encodeBase64(encryptedValue);
		return encodedValue;
	}
	
	/**
	 * Decrypts data using the decryption key. Performs the opposite of the
	 * <code>decrypt(String)</code> function.
	 * 
	 * @param ciphertext The data to be decrypted, assumed to be encoded in
	 *        base-64.
	 * @return The cleartext message.
	 * 
	 * @throws UnsupportedEncodingException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IllegalStateException If the decryption cipher hasn't been set.
	 * @see Base64
	 */
	public byte[] decrypt(final String ciphertext) throws IllegalBlockSizeException, BadPaddingException {
		if (decryptionCipher == null)
			throw new IllegalStateException("Cannot perform decryption without a decryption cipher.");
		
		return decrypt(ciphertext.getBytes());
	}
	
	/**
	 * Decrypts data using the decryption key. Performs the opposite of the
	 * <code>encrypt(byte[])</code> function.
	 * 
	 * @param ciphertext The data to be decrypted, assumed to be encoded in
	 *        base-64.
	 * @return The cleartext message.
	 * 
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IllegalStateException If the decryption cipher hasn't been set.
	 * @see Base64
	 */
	public byte[] decrypt(final byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException {
		if (decryptionCipher == null)
			throw new IllegalStateException("Cannot perform decryption without a decryption cipher.");
		
		final byte[] decodedValue = Base64.decodeBase64(ciphertext);
		final byte[] decryptedValue = decryptionCipher.doFinal(decodedValue);
		return decryptedValue;
	}
}

/******************************************************************************
 * END OF FILE: Encryption.java
 *****************************************************************************/
