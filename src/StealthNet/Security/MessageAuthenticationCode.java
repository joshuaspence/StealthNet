/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        MessageAuthenticationCode.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     An interface to provide StealthNet with Message 
 * 					Authentication Codes (MACs) for testing packet integrity.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet.Security;

/* Import Libraries ******************************************************** */

import javax.management.InvalidAttributeValueException;

import org.apache.commons.codec.binary.Base64;

/* StealthNet.Security.MessageAuthenticationCode Interface Definition ****** */

/**
 * An interface to calculate and verify packet Message Authentication Codes
 * (MACs). This is used to ensure packet integrity between peers. <p> When a
 * packet is sent, the sender calculates the MAC for the packet and appends it
 * to the message. When a packet is received, the receiver calculates the MAC
 * for the packet (disregarding the MAC digest) and compares it to the received
 * MAC digest. If the calculated digest matches the received digest, then the
 * receiver can be assured of the message integrity. <p> In order for this to
 * occur, the sender and receiver must at some stage exchange an
 * "integrity key", used as a key for the hash function.
 * 
 * @author Joshua Spence
 */
public interface MessageAuthenticationCode {
	/**
	 * Calculates the Message Authentication Code (MAC) for the given data.
	 * 
	 * @param data The data to calculate the Message Authentication Codes (MAC)
	 *        for.
	 * @return The digest of the given message, encoded in base-64.
	 * 
	 * @throws InvalidAttributeValueException
	 * @see Base64
	 */
	public byte[] createMAC(String data) throws InvalidAttributeValueException;
	
	/**
	 * Calculates the Message Authentication Code (MAC) for the given data.
	 * 
	 * @param data The data to calculate the Message Authentication Codes (MAC)
	 *        for.
	 * @return The digest of the given message, encoded in base-64.
	 * 
	 * @throws InvalidAttributeValueException
	 * @see Base64
	 */
	public byte[] createMAC(byte[] data) throws InvalidAttributeValueException;
	
	/**
	 * Verifies the given data against a given Message Authentication Code (MAC)
	 * digest.
	 * 
	 * @param data The data to check the digest of.
	 * @param digest The given Message Authentication Codes (MAC) digest,
	 *        assumed to be encoded in base-64.
	 * 
	 * @return True if the message matches the given MAC digest, otherwise
	 *         false.
	 * 
	 * @throws InvalidAttributeValueException
	 * @see Base64
	 */
	public boolean verifyMAC(String data, byte[] digest) throws InvalidAttributeValueException;
	
	/**
	 * Verifies the given data against a given Message Authentication Codes
	 * (MAC) digest.
	 * 
	 * @param data The data to check the digest of.
	 * @param digest The given Message Authentication Codes (MAC) digest,
	 *        assumed to be encoded in bsae-64.
	 * 
	 * @return True if the message matches the given MAC digest, otherwise
	 *         false.
	 * 
	 * @throws InvalidAttributeValueException
	 * @see Base64
	 */
	public boolean verifyMAC(byte[] data, byte[] digest) throws InvalidAttributeValueException;
}

/******************************************************************************
 * END OF FILE: MessageAuthenticationCode.java
 *****************************************************************************/
