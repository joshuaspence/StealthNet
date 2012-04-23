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

package StealthNet.Security;

/* Import Libraries **********************************************************/

import javax.management.InvalidAttributeValueException;

/* StealthNet.Security.MessageAuthenticationCode Interface Definition ********/

/**
 * An interface to calculate and verify packet Message Authentication Codes 
 * (MACs). This is used to ensure packet integrity between peers.
 * 
 * When a packet is sent, the sender calculates the MAC for the packet and 
 * appends it to the message. When a packet is received, the receiver calculates
 * the MAC for the packet (without the MAC digest) and compares it to the
 * received MAC digest. If the calculated digest matches the received digest, 
 * then the receiver can be assured of the message integrity.
 * 
 * In order for this to occur, the sender and receiver must at some stage 
 * exchange an "integrity key", used as a key for the hash function.
 * 
 * @author Joshua Spence
 */
public interface MessageAuthenticationCode {	
	/**
	 * Calculates the Message Authentication Code (MAC) for a given message.
	 * 
	 * @param packetContents The message to calculate the Message Authentication 
	 * Codes (MAC) for.
	 * @return The digest of the given message (in base-64 encoding).
	 * 
	 * @throws InvalidAttributeValueException 
	 */
	public byte[] createMAC(String packetContents) throws InvalidAttributeValueException;
	
	/**
	 * Calculates the Message Authentication Code (MAC) for a given message.
	 * 
	 * @param packetContents The message to calculate the Message Authentication 
	 * Codes (MAC) for.
	 * @return The digest of the given message (in base-64 encoding).
	 * 
	 * @throws InvalidAttributeValueException 
	 */
	public byte[] createMAC(byte[] packetContents) throws InvalidAttributeValueException;

	
	/**
	 * Verifies a given message against a given Message Authentication Codes 
	 * (MAC) digest.
	 * 
	 * @param packetContents The message to check.
	 * @param mac The given Message Authentication Codes (MAC) digest (in 
	 * base-64 encoding).
	 * 
	 * @return True if the message matches the given MAC digest, otherwise 
	 * false.
	 * 
	 * @throws InvalidAttributeValueException 
	 */
	public boolean verifyMAC(String packetContents, byte[] mac) throws InvalidAttributeValueException;
	
	/**
	 * Verifies a given message against a given Message Authentication Codes 
	 * (MAC) digest.
	 * 
	 * @param packetContents The message to check.
	 * @param mac The given Message Authentication Codes (MAC) digest (in 
	 * base-64 encoding).
	 * 
	 * @return True if the message matches the given MAC digest, otherwise 
	 * false.
	 * 
	 * @throws InvalidAttributeValueException 
	 */
	public boolean verifyMAC(byte[] packetContents, byte[] mac) throws InvalidAttributeValueException;
}

/******************************************************************************
 * END OF FILE:     MessageAuthenticationCode.java
 *****************************************************************************/