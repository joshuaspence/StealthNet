/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Securtity
 * FILENAME:        Encryption.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     An abstract class to provide the encryption and decryption
 * 					of packets in StealthNet.
 *
 *****************************************************************************/

package StealthNet.Security;

/* Import Libraries **********************************************************/

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

/* StealthNet.Security.Encryption Class Definition **************************/

/**
 * An abstract class to provide encryption and decryption of messages, in order
 * to provide confidentiality of the communications in StealthNet.
 * 
 * Ideally, only the sender should be able to encrypt the message; and only the
 * receiver should be able to decrypt the message.
 * 
 * @author Joshua Spence
 */
public abstract class Encryption {
	/** Keys and ciphers. */
	protected Key encryptionKey;
	protected Cipher encryptionCipher;
	protected Key decryptionKey;
	protected Cipher decryptionCipher;

	/** Constants. */
	private final String algorithm;

	/**
	 * Constructor
	 * 
	 * @param algorithm The cipher algorithm to be used.
	 */
	protected Encryption(final String algorithm) {
		this.algorithm = algorithm;
	}

	/**
	 * Set the encryption cipher and key.
	 * 
	 * @param key The key used for encryption.
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
	 * Set the encryption cipher and key.
	 * 
	 * @param key The key used for encryption.
	 * @param specs The algorithm parameter specifications for the cipher.
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
	 * Set the decryption cipher and key.
	 * 
	 * @param key The key used for decryption.
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
	 * Set the decryption cipher and key.
	 * 
	 * @param key The key used for encryption.
	 * @param specs The algorithm parameter specifications for the cipher.
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
	 * Encrypts a message using the encryption key. Performs the opposite of the
	 * decrypt(String) function.
	 * 
	 * @param cleartext The message to encrypt.
	 * @return The encrypted message, encoded in base 64.
	 * 
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * 
	 */
	public byte[] encrypt(final String cleartext) throws IllegalBlockSizeException, BadPaddingException {
		if (encryptionCipher == null)
			throw new IllegalStateException("Cannot perform encryption without a decryption cipher.");

		return encrypt(cleartext.getBytes());
	}

	/**
	 * Encrypts a message using the encryption key. Performs the opposite of the
	 * decrypt(byte[]) function.
	 * 
	 * @param cleartext The message to encrypt.
	 * @return The encrypted message, encoded in base 64.
	 * 
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public byte[] encrypt(final byte[] cleartext) throws IllegalBlockSizeException, BadPaddingException {
		if (encryptionCipher == null)
			throw new IllegalStateException("Cannot perform encryption without a decryption cipher.");

		final byte[] encryptedValue = encryptionCipher.doFinal(cleartext);
		final byte[] encodedValue = Base64.encodeBase64(encryptedValue);
		return encodedValue;
	}

	/**
	 * Decrypts a message using the decryption key. Performs the opposite of the
	 * encrypt(String) function.
	 * 
	 * @param ciphertext The message to be decrypted, assumed to be encoded in
	 * base 64.
	 * @return The cleartext message.
	 * 
	 * @throws UnsupportedEncodingException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public byte[] decrypt(final String ciphertext) throws IllegalBlockSizeException, BadPaddingException {
		if (decryptionCipher == null)
			throw new IllegalStateException("Cannot perform decryption without a decryption cipher.");

		return decrypt(ciphertext.getBytes());
	}

	/**
	 * Decrypts a message using the decryption key. Performs the opposite of the
	 * encrypt(byte[]) function.
	 * 
	 * @param ciphertext The message to be decrypted, assumed to be encoded in
	 * base 64.
	 * @return The cleartext message.
	 * 
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
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
 * END OF FILE:     Encryption.java
 *****************************************************************************/