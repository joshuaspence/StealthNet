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

/* StealthNet.Security.HashedMessageAuthenticationCode Class Definition **** */

/**
 * A class to calculate a verify packet HMACs.
 * 
 * @author Joshua Spence
 */
public class HashedMessageAuthenticationCode implements MessageAuthenticationCode {
	/** The secret key used for creating hash digests. */
	private final SecretKey key;
	
	/** The Mac instance used to create digests. */
	private final Mac mac;
	
	/** Constants. */
	public static final String HMAC_ALGORITHM = "HmacSHA1";
	
	/**
	 * The expected fixed number of bytes of the digest produced by this MAC
	 * function. We need to know this so that we don't have to encode the data
	 * length and digest length into the transmitted string.
	 */
	public static final int DIGEST_BYTES = 20;
	
	/**
	 * Constructor
	 * 
	 * @param key The key to use for the HMAC algorithm.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public HashedMessageAuthenticationCode(final SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
		this.key = key;
		
		/** Create a MAC object using HMAC-SHA1 and initialise with key. */
		mac = Mac.getInstance(HMAC_ALGORITHM);
		mac.init(this.key);
	}
	
	/**
	 * Calculates the MAC for a given message.
	 * 
	 * @param packetContents The message to calculate the MAC for.
	 * @return The digest of the given message (in base-64 encoding).
	 * @throws InvalidAttributeValueException
	 */
	@Override
	public byte[] createMAC(final String packetContents) throws InvalidAttributeValueException {
		return createMAC(packetContents.getBytes());
	}
	
	/**
	 * Calculates the MAC for a given message.
	 * 
	 * @param packetContents The message to calculate the MAC for.
	 * @return The digest of the given message (in base-64 encoding).
	 * @throws InvalidAttributeValueException
	 */
	@Override
	public byte[] createMAC(final byte[] packetContents) throws InvalidAttributeValueException {
		final byte[] digest = mac.doFinal(packetContents);
		
		/** A sanity check. */
		if (digest.length != DIGEST_BYTES)
			throw new InvalidAttributeValueException("Actual digest size does not match specified digest size. Specified size: " + DIGEST_BYTES + ". Actual size: " + digest.length + ".");
		
		return digest;
	}
	
	/**
	 * Verifies a given message against a given MAC digest.
	 * 
	 * @param packetContents The message to check.
	 * @param mac The given MAC digest (in base-64 encoding).
	 * 
	 * @return True if the message matches the given MAC digest, otherwise
	 *         false.
	 * 
	 * @throws InvalidAttributeValueException
	 */
	@Override
	public boolean verifyMAC(final String packetContents, final byte[] mac) throws InvalidAttributeValueException {
		return verifyMAC(packetContents.getBytes(), mac);
	}
	
	/**
	 * Verifies a given message against a given MAC.
	 * 
	 * @param packetContents The message to check.
	 * @param mac The given MAC digest (in base-64 encoding).
	 * 
	 * @return True if the message matches the given MAC digest, otherwise
	 *         false.
	 * 
	 * @throws InvalidAttributeValueException
	 */
	@Override
	public boolean verifyMAC(final byte[] packetContents, final byte[] mac) throws InvalidAttributeValueException {
		final byte[] digest = createMAC(packetContents);
		
		/** Compare the two digests */
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
