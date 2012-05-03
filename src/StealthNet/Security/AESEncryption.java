/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        AESEncryption.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     Implementation of AES encryption for encrypting and
 * 					decrypting StealthNet communications.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet.Security;

/* Import Libraries ******************************************************** */

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* StealthNet.Security.AESEncryption Class Definition ********************** */

/**
 * A class used to encrypt and decrypt messages using AES.
 * 
 * @author Joshua Spence
 * @see Encryption
 */
public class AESEncryption extends Encryption {
	private final IvParameterSpec ips;
	
	/**
	 * {@link MessageDigest} algorithm to use to generate a {@link SecretKey}
	 * for encryption and decryption.
	 */
	public static final String HASH_ALGORITHM = "MD5";
	
	/**
	 * Algorithm used by {@link SecretKeySpec} to generate a {@link SecretKey}
	 * for encryption and decryption.
	 */
	public static final String KEY_ALGORITHM = "AES";
	
	/** The algorithm used to specify the encryption and decryption ciphers. */
	public static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
	
	/**
	 * Number of bytes to use as a salt for the encryption and decryption
	 * ciphers.
	 */
	private static final int SALT_BYTES = 16;
	
	/**
	 * Constructor to use a supplied {@link SecretKey} for encryption and
	 * decryption.
	 * 
	 * @param key The {@link SecretKey} to be used for both encryption and
	 *        decryption.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 */
	public AESEncryption(final SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		super(CIPHER_ALGORITHM);
		
		/*
		 * Generate the initialisation vector using a seeded random number
		 * generator, with the seed equal to the hash of the encryption key. In
		 * this way, both peers should generate the same initialisation vectors.
		 * 
		 * NOTE: IVGenerator must be of class Random and not SecureRandom.
		 * Otherwise the peers will generate different initialisation vectors,
		 * despite having the same seed to the random number generator.
		 */
		final byte[] iv = new byte[SALT_BYTES];
		final long salt = key.hashCode();
		final Random IVGenerator = new Random(salt);
		
		for (int i = 0; i < 16; i++)
			iv[i] = (byte) IVGenerator.nextInt();
		ips = new IvParameterSpec(iv);
		
		super.setEncryption(key, ips);
		super.setDecryption(key, ips);
	}
}

/******************************************************************************
 * END OF FILE: AESEncryption.java
 *****************************************************************************/
