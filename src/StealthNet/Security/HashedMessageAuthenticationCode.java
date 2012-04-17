/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        HashedMessageAuthenticationCode.java
 * AUTHORS:         Joshua Spence and Ahmad Al Mutawa
 * DESCRIPTION:     Implementation of a Hashed Message Authentication Code 
 * 					(HMAC) for StealthNet communications.
 * VERSION:         1.0
 *
 *****************************************************************************/

package StealthNet.Security;

/* Import Libraries **********************************************************/

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;

/* StealthNet.Security.HashedMessageAuthenticationCode Class Definition ******/

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
	
	/** String constants. */
	public static final String HMAC_ALGORITHM = "HmacMD5";
	
	/**
	 * Constructor
	 * 
	 * @param key The key to use for the HMAC algorithm.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public HashedMessageAuthenticationCode(SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
		this.key = key;
		
		/** Create a MAC object using HMAC-MD5 and initialise with key. */
		this.mac = Mac.getInstance(HMAC_ALGORITHM);
	    this.mac.init(this.key);
	}
	
	/**
	 * Calculates the MAC for a given message.
	 * 
	 * @param message The message to calculate the MAC for.
	 * @return The digest of the given message (in base-64 encoding).
	 */
	public String createMAC(String message) {
	    return createMAC(message.getBytes());
	}
	
	/**
	 * Calculates the MAC for a given message.
	 * 
	 * @param message The message to calculate the MAC for.
	 * @return The digest of the given message (in base-64 encoding).
	 */
	private String createMAC(byte[] message) {
		byte[] digest = this.mac.doFinal(message);
		return Base64.encodeBase64String(digest);
	}
	
	/**
	 * Verifies a given message against a given MAC digest.
	 * 
	 * @param message The message to check.
	 * @param mac The given MAC digest (in base-64 encoding).
	 * 
	 * @return True if the message matches the given MAC digest, otherwise 
	 * false.
	 */
	public boolean verifyMAC(String message, byte[] mac) {
		return verifyMAC(message.getBytes(), mac);
	}
	
	/**
	 * Verifies a given message against a given MAC.
	 * 
	 * @param message The message to check.
	 * @param mac The given MAC digest (in base-64 encoding).
	 * 
	 * @return True if the message matches the given MAC digest, otherwise 
	 * false.
	 */
	public boolean verifyMAC(byte[] message, byte[] mac) {
		final byte[] digest = this.mac.doFinal(message);
		final byte[] digest_base64 = Base64.encodeBase64String(digest).getBytes();
		
		if (digest_base64.length != mac.length) {
	        return false;
	    } else {
	        for (int i = 0; i < mac.length; i++)
	            if (mac[i] != digest_base64[i])
	                return false;
	    }
		
		return true;
	}
}

/******************************************************************************
 * END OF FILE:     HashedMessageAuthenticationCode.java
 *****************************************************************************/