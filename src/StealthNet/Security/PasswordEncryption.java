/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        AESEncryption.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     Implementation of password-based encryption for encrypting  
 * 					and decrypting StealthNet communications.
 *
 *****************************************************************************/

package StealthNet.Security;

/* Import Libraries **********************************************************/

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Base64;

/* StealthNet.Security.PasswordEncryption Class Definition *******************/

/**
 * A class used to encrypt and decrypt messages using a password.
 * 
 * @author Joshua Spence
 */
public class PasswordEncryption implements Encryption {
	/** Keys and ciphers */
	private final String password;
	private final byte[] salt;
	private final SecretKey key;
	private final PBEParameterSpec params;
	private final Cipher encryptionCipher;
	private final Cipher decryptionCipher;
	
	/** Constants. */
	private static final String SECURERANDOM_ALGORITHM = "SHA1PRNG";
	public static final int SALT_BYTES = 8;
	private static final int ALGORITHM_ITERATIONS = 1000;
	private static final String KEYFACTORY_ALGORITHM = "PBEWithMD5AndDES";
	
	/**
	 * Constructor with a randomly generated salt.
	 * 
	 * @param password The password to be used for encryption and decryption. 
	 * Note that the password cannot be null.
	 * 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeyException 
	 */
	public PasswordEncryption(String password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		if (password == null)
			throw new IllegalArgumentException("Password cannot be null.");
		this.password = password;
		
		/** Generate a random salt. */
		final SecureRandom rand = SecureRandom.getInstance(SECURERANDOM_ALGORITHM);
		this.salt = new byte[SALT_BYTES];
		rand.nextBytes(this.salt);
		
		/** Setup encryption. */
		this.params = new PBEParameterSpec(this.salt, ALGORITHM_ITERATIONS);
		final PBEKeySpec keySpec = new PBEKeySpec(this.password.toCharArray());
		final SecretKeyFactory factory = SecretKeyFactory.getInstance(KEYFACTORY_ALGORITHM);
		this.key = factory.generateSecret(keySpec);
		
		/** Setup encryption cipher. */
		this.encryptionCipher = Cipher.getInstance(KEYFACTORY_ALGORITHM);
		this.encryptionCipher.init(Cipher.ENCRYPT_MODE, this.key, this.params);
		
		/** Setup decryption cipher. */
		this.decryptionCipher = Cipher.getInstance(KEYFACTORY_ALGORITHM);
		this.decryptionCipher.init(Cipher.DECRYPT_MODE, this.key, this.params);
	}
	
	/**
	 * Constructor with a specified salt.
	 * 
	 * @param salt The salt to use for encryption and decryption.
	 * @param password The password to be used for encryption and decryption. 
	 * Note that the password cannot be null.
	 * 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeyException 
	 */
	public PasswordEncryption(byte[] salt, String password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		if (password == null)
			throw new IllegalArgumentException("Password cannot be null.");
		this.password = password;
		
		if (salt.length != SALT_BYTES)
			throw new IllegalArgumentException("Salt must be " + SALT_BYTES + " bytes.");
		this.salt = salt;
		
		/** Setup encryption. */
		this.params = new PBEParameterSpec(this.salt, ALGORITHM_ITERATIONS);
		final PBEKeySpec keySpec = new PBEKeySpec(this.password.toCharArray());
		final SecretKeyFactory factory = SecretKeyFactory.getInstance(KEYFACTORY_ALGORITHM);
		this.key = factory.generateSecret(keySpec);
		
		/** Setup encryption cipher. */
		this.encryptionCipher = Cipher.getInstance(KEYFACTORY_ALGORITHM);
		this.encryptionCipher.init(Cipher.ENCRYPT_MODE, this.key, this.params);
		
		/** Setup decryption cipher. */
		this.decryptionCipher = Cipher.getInstance(KEYFACTORY_ALGORITHM);
		this.decryptionCipher.init(Cipher.DECRYPT_MODE, this.key, this.params);
	}
	
	/**
	 * Encrypts a message using the encryption key. Performs the opposite of the
	 * decrypt(String) function.
	 * 
	 * @param cleartext The message to encrypt.
	 * @return The encrypted message, encoded in base 64.
	 * 
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] encrypt(String cleartext) throws IllegalBlockSizeException, BadPaddingException {
		return encrypt(cleartext.getBytes());
	}
	
	/**
	 * Encrypts a message using the encryption key. Performs the opposite of the
	 * decrypt(byte[]) function.
	 * 
	 * @param cleartext The message to encrypt.
	 * @return The encrypted message, encoded in base 64.
	 * 
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] encrypt(byte[] cleartext) throws IllegalBlockSizeException, BadPaddingException {		
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
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * 
	 */
	public byte[] decrypt(String ciphertext) throws IllegalBlockSizeException, BadPaddingException {	 
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
	public byte[] decrypt(byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException  {
		final byte[] decodedValue = Base64.decodeBase64(ciphertext);
		final byte[] decryptedValue = decryptionCipher.doFinal(decodedValue);
		return decryptedValue;
	}
	
	/**
	 * Get the salt that was used for encryption and decryption.
	 * 
	 * @return The salt that was used for encryption and decryption.
	 */
	public byte[] getSalt() {
		return this.salt;
	}
	
	/**
	 * Get the secret key generated by the password.
	 * 
	 * @return The secret key generated as a result of the input password.
	 */
	public SecretKey getSecretKey() {
		return this.key;
	}
}

/******************************************************************************
 * END OF FILE:     PasswordEncryption.java
 *****************************************************************************/