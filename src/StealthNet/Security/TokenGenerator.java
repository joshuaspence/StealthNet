/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        TokenGenerator.java
 * AUTHORS:         Joshua Spence and Ahmad Al Mutawa
 * DESCRIPTION:     An interface to create token identifiers for StealthNet
 * 					packets to prevent replay attacks.
 * VERSION:         1.0
 *
 *****************************************************************************/

package StealthNet.Security;

/* Import Libraries **********************************************************/

/* StealthNet.Security.TokenGenerator Interface Definition *******************/

/**
 * An interface to create token identifiers for StealthNet packets. This is used
 * to prevent message replay attacks by "generating" and "consuming" tokens.
 * 
 * When a packet is sent, a token is generated and appended to the message. At
 * the receiving end of the communications, the peer is able to check if a 
 * message with the received token has been received before. If yes, then this
 * packet is probably a replay, and is consequently discarded silently.
 * 
 * @author Joshua Spence
 */
public interface TokenGenerator {	
	/** 
	 * Check if a given token is the expected token.
	 * 
	 * @param tok The token that was received.
	 * @return True if the received token has not been consumed. False 
	 * otherwise.
	 */
	public boolean isAllowed(long tok);
	
	/**
	 * Gets the seed for the TokenGenerators, that other peers can use to 
	 * replicate the token generator sequence.
	 * 
	 * @return The seed used to initialise the TokenGenerator.
	 */
	public long getSeed();
}

/******************************************************************************
 * END OF FILE:     TokenGenerator.java
 *****************************************************************************/