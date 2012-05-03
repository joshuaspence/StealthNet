/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        HashedMessageAuthenticationCode.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     Implementation of a Hashed Message Authentication Code 
 * 					(HMAC) for StealthNet communications.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet.Security;

/* Import Libraries ******************************************************** */

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.management.InvalidAttributeValueException;

import org.apache.commons.codec.binary.Base64;

import StealthNet.EncryptedPacket;

/* StealthNet.Security.HashedMessageAuthenticationCode Class Definition **** */

/**
 * A class to calculate a verify packet Hashed Message Authentication Codes
 * (HMACs).
 * 
 * @author Joshua Spence
 * @see MessageAuthenticationCode
 */
public class HashedMessageAuthenticationCode implements MessageAuthenticationCode {
	/** The {@link SecretKey} used for creating hash digests. */
	private final SecretKey key;
	
	/** The {@link Mac} instance used to create digests. */
	private final Mac mac;
	
	/** The algorithm used to initialise the {@link Mac}. */
	public static final String HMAC_ALGORITHM = "HmacSHA1";
	
	/**
	 * The expected fixed number of bytes of the digest produced by this
	 * {@link MessageAuthenticationCode} function. We need to know this so that
	 * we don't have to encode the data length and digest length into the
	 * transmitted string.
	 * 
	 * @see EncryptedPacket
	 */
	public static final int DIGEST_BYTES = 20;
	
	/**
	 * Constructor.
	 * 
	 * @param key The {@link SecretKey} to use for the Hashed
	 *        {@link MessageAuthenticationCode} algorithm.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public HashedMessageAuthenticationCode(final SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
		this.key = key;
		
		/* Create a MAC object using HMAC-SHA1 and initialise with key. */
		mac = Mac.getInstance(HMAC_ALGORITHM);
		mac.init(this.key);
	}
	
	/**
	 * Calculates the {@link MessageAuthenticationCode} digest for the given
	 * data.
	 * 
	 * @param data The data to calculate the {@link MessageAuthenticationCode}
	 *        digest for.
	 * @return The digest of the given given, encoded in base-64.
	 * @throws InvalidAttributeValueException
	 * @see Base64
	 */
	@Override
	public byte[] createMAC(final String data) throws InvalidAttributeValueException {
		return createMAC(data.getBytes());
	}
	
	/**
	 * Calculates the {@link MessageAuthenticationCode} digest for the given
	 * data.
	 * 
	 * @param data The data to calculate the MAC digest for.
	 * @return The digest of the given data, encoded in base-64.
	 * @throws InvalidAttributeValueException
	 * @see Base64
	 */
	@Override
	public byte[] createMAC(final byte[] data) throws InvalidAttributeValueException {
		final byte[] digest = mac.doFinal(data);
		
		/* A sanity check. */
		if (digest.length != DIGEST_BYTES)
			throw new InvalidAttributeValueException("Actual digest size does not match specified digest size. Specified size: " + DIGEST_BYTES + ". Actual size: " + digest.length + ".");
		
		return digest;
	}
	
	/**
	 * Verifies the given data against a given {@link MessageAuthenticationCode}
	 * digest.
	 * 
	 * @param data The data to check the {@link MessageAuthenticationCode}
	 *        digest of.
	 * @param mac The given {@link MessageAuthenticationCode} digest, encoded in
	 *        base-64.
	 * 
	 * @return True if the digest of the data matches the given
	 *         {@link MessageAuthenticationCode} digest, otherwise false.
	 * 
	 * @throws InvalidAttributeValueException
	 * @see Base64
	 */
	@Override
	public boolean verifyMAC(final String data, final byte[] mac) throws InvalidAttributeValueException {
		return verifyMAC(data.getBytes(), mac);
	}
	
	/**
	 * Verifies the given data against a given MAC digest.
	 * 
	 * @param data The data to check the {@link MessageAuthenticationCode}
	 *        digest of.
	 * @param mac The given {@link MessageAuthenticationCode} digest, encoded in
	 *        base-64.
	 * 
	 * @return True if the message matches the given MAC digest, otherwise
	 *         false.
	 * 
	 * @throws InvalidAttributeValueException
	 * @see Base64
	 */
	@Override
	public boolean verifyMAC(final byte[] data, final byte[] mac) throws InvalidAttributeValueException {
		final byte[] digest = createMAC(data);
		
		/* Compare the two digests */
		if (digest.length != mac.length)
			return false;
		else
			for (int i = 0; i < mac.length; i++)
				if (mac[i] != digest[i])
					return false;
		
		return true;
	}
}

/******************************************************************************
 * END OF FILE: HashedMessageAuthenticationCode.java
 *****************************************************************************/
