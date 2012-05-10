/* @formatter:off */
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
/* @formatter:on */

package StealthNet.Security;

/* Import Libraries ******************************************************** */

/* StealthNet.Security.NonceGenerator Interface Definition ***************** */

/**
 * An interface to create nonce identifiers for StealthNet packets. This is used
 * to prevent message replay attacks by "generating" and "consuming" nonces.
 * 
 * <p> A nonce is stored as a byte array of 8 bytes. When a packet is sent, a
 * nonce is generated and appended to the message. At the receiving end of the
 * communications, the peer is able to check if a message with the received
 * nonce has been received before. If yes, then this packet is probably a
 * replay, and is consequently discarded silently.
 * 
 * @author Joshua Spence
 */
public interface NonceGenerator {
	/**
	 * Check if a given nonce is valid.
	 * 
	 * @param nonce The nonce that was received.
	 * @return True if the received nonce has not yet been consumed. False
	 *         otherwise.
	 */
	public boolean isAllowed(byte[] nonce);
	
	/**
	 * Gets the next nonce produced by the {@link NonceGenerator}.
	 * 
	 * @return The next token produced by the {@link NonceGenerator}.
	 */
	public byte[] getNext();
	
	/**
	 * Gets the seed for the {@link NonceGenerator}, that other peers can use to
	 * replicate the {@link NonceGenerator} sequence. It is not always necessary
	 * that the partner instances of the {@link NonceGenerator} generate the
	 * same tokens in the same order. In some instances it is enough that each
	 * generated nonce is unique.
	 * 
	 * @return The seed used to initialise the {@link NonceGenerator}.
	 */
	public byte[] getSeed();
}

/******************************************************************************
 * END OF FILE: NonceGenerator.java
 *****************************************************************************/
