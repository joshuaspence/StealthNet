package StealthNet;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;

/**
 * Calculates a verifies packet checksums. This is used to ensure packet 
 * integrity between hosts.
 * 
 * @author Joshua Spence
 */
public class StealthNetMAC {
	/** 
	 * Set to true in build.xml to output debug messages for this class. 
	 * Alternatively, use the argument `-Ddebug.StealthNetChecksum=true' at the 
	 * command line.
	 */
	private static final boolean DEBUG = true && System.getProperty("debug.StealthNetChecksum", "false").equals("true");
	
	private final SecretKey key;
	private final Mac mac;
	
	public static final String HMAC_ALGORITHM = "HmacMD5";
	
	public StealthNetMAC(SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
		this.key = key;
		
		/** Create a MAC object using HMAC-MD5 and initialize with key. */
		this.mac = Mac.getInstance(HMAC_ALGORITHM);
	    this.mac.init(this.key);
	}
	
	/**
	 * Calculates the MAC for a given message.
	 * 
	 * @param message The message to calculate the MAC for.
	 * @return The digest of the given message.
	 */
	public String createMAC(String message) {
		if (DEBUG) System.out.println("Creating checksum for message \"" + message + "\".");
	    byte[] messageBytes = message.getBytes();
	    return createMAC(messageBytes);
	}
	
	/**
	 * Calculates the MAC for a given message.
	 * 
	 * @param message The message to calculate the MAC for.
	 * @return The digest of the given message.
	 */
	public String createMAC(byte[] message) {
		byte[] digest = this.mac.doFinal(message);
		return Base64.encodeBase64String(digest);
	}
	
	/**
	 * Verifies a given message against a given MAC digest.
	 * 
	 * @param message The message to check.
	 * @param mac The given MAC digest.
	 * 
	 * @return True if the message matches the given MAC digest, otherwise 
	 * false.
	 */
	public boolean verifyMAC(String message, byte[] mac) {
		if (DEBUG) System.out.println("Verifying MAC \"" + new String(mac) + "\" for message \"" + new String(message) + "\".");
		return verifyMAC(message.getBytes(), mac);
	}
	
	/**
	 * Verifies a given message against a given MAC.
	 * 
	 * @param message The message to check.
	 * @param mac The given MAC digest.
	 * 
	 * @return True if the message matches the given MAC digest, otherwise 
	 * false.
	 */
	public boolean verifyMAC(byte[] message, byte[] mac) {
		byte[] digest = this.mac.doFinal(message);
		
		if (digest.length != mac.length) {
	        return false;
	    } else {
	        for (int i = 0; i < mac.length; i++)
	            if (mac[i] != digest[i])
	                return false;
	    }
		
		return true;
	}
}
