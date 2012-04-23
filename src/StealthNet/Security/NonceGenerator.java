/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        NonceGenerator.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     An interface to create nonce identifiers for StealthNet
 * 					packets to prevent replay attacks.
 *
 *****************************************************************************/

package StealthNet.Security;

/* Import Libraries **********************************************************/

/* StealthNet.Security.NonceGenerator Interface Definition *******************/

/**
 * An interface to create nonce identifiers for StealthNet packets. This is used
 * to prevent message replay attacks by "generating" and "consuming" nonces.
 * 
 * A nonce is stored as a byte array of 8 bytes.
 * 
 * When a packet is sent, a nonce is generated and appended to the message. At
 * the receiving end of the communications, the peer is able to check if a 
 * message with the received nonce has been received before. If yes, then this
 * packet is probably a replay, and is consequently discarded silently.
 * 
 * @author Joshua Spence
 */
public interface NonceGenerator {	
	/** 
	 * Check if a given nonce is a valid nonce.
	 * 
	 * @param nonce The nonce that was received.
	 * @return True if the received nonce has not yet been consumed. False 
	 * otherwise.
	 */
	public boolean isAllowed(byte[] nonce);
	
	/**
	 * Gets the next nonce produced by the NonceGenerator.
	 * 
	 * @return The next token produced by the NonceGenerator.
	 */
	public byte[] getNext();
	
	/**
	 * Gets the seed for the NonceGenerator, that other peers can use to 
	 * replicate the nonce generator sequence.
	 * 
	 * @return The seed used to initialise the NonceGenerator.
	 */
	public byte[] getSeed();
}

/******************************************************************************
 * END OF FILE:     NonceGenerator.java
 *****************************************************************************/