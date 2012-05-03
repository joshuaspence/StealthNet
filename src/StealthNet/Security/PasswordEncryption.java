/* @formatter:off */
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
/* @formatter:on */

package StealthNet.Security;

/* Import Libraries ******************************************************** */

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/* StealthNet.Security.PasswordEncryption Class Definition ***************** */

/**
 * A class used to encrypt and decrypt messages using a password.
 * 
 * @author Joshua Spence
 */
public class PasswordEncryption extends Encryption {
	/** Keys and ciphers */
	private final String password;
	private final SecretKey key;
	private final byte[] salt;
	private final PBEParameterSpec params;
	
	/** Constants. */
	public static final String ALGORITHM = "PBEWithMD5AndDES";
	public static final int SALT_BYTES = 8;
	private static final String SECURERANDOM_ALGORITHM = "SHA1PRNG";
	private static final int ALGORITHM_ITERATIONS = 1000;
	
	/**
	 * Constructor with a randomly generated salt.
	 * 
	 * @param password The password to be used for encryption and decryption.
	 *        Note that the password cannot be null.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 */
	public PasswordEncryption(final String password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		super(ALGORITHM);
		
		if (password == null)
			throw new IllegalArgumentException("Password cannot be null.");
		this.password = password;
		
		/** Generate a random salt. */
		final SecureRandom rand = SecureRandom.getInstance(SECURERANDOM_ALGORITHM);
		salt = new byte[SALT_BYTES];
		rand.nextBytes(salt);
		
		/** Setup encryption. */
		params = new PBEParameterSpec(salt, ALGORITHM_ITERATIONS);
		final PBEKeySpec keySpec = new PBEKeySpec(this.password.toCharArray());
		final SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
		key = factory.generateSecret(keySpec);
		
		super.setEncryption(key, params);
		super.setDecryption(key, params);
	}
	
	/**
	 * Constructor with a specified salt.
	 * 
	 * @param salt The salt to use for encryption and decryption.
	 * @param password The password to be used for encryption and decryption.
	 *        Note that the password cannot be null.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 */
	public PasswordEncryption(final byte[] salt, final String password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		super(ALGORITHM);
		
		if (password == null)
			throw new IllegalArgumentException("Password cannot be null.");
		this.password = password;
		
		if (salt.length != SALT_BYTES)
			throw new IllegalArgumentException("Salt must be " + SALT_BYTES + " bytes.");
		this.salt = salt;
		
		/** Setup encryption. */
		params = new PBEParameterSpec(this.salt, ALGORITHM_ITERATIONS);
		final PBEKeySpec keySpec = new PBEKeySpec(this.password.toCharArray());
		final SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
		key = factory.generateSecret(keySpec);
		
		super.setEncryption(key, params);
		super.setDecryption(key, params);
	}
	
	/**
	 * Get the salt that was used for encryption and decryption.
	 * 
	 * @return The salt that was used for encryption and decryption.
	 */
	public byte[] getSalt() {
		return salt;
	}
	
	/**
	 * Get the secret key generated by the password.
	 * 
	 * @return The secret key generated as a result of the input password.
	 */
	public SecretKey getSecretKey() {
		return key;
	}
}

/******************************************************************************
 * END OF FILE: PasswordEncryption.java
 *****************************************************************************/
