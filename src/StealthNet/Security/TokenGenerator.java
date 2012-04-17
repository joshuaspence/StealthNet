/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie and Stephen Gould
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

/* TokenGenerator Interface Definition ***************************************/

/**
 * An interface to create token identifiers for StealthNet packets. This is used
 * to prevent message replay attacks because both parties should be able to 
 * predict the next expected token.
 * 
 * @author Joshua Spence
 */
public interface TokenGenerator {	
	/** 
	 * Check if a given token is the expected token.
	 * 
	 * @param tok The token that was received.
	 * @return True if the received token matches the expected token, false 
	 * otherwise.
	 */
	public boolean isAllowed(long tok);
	
	/**
	 * Gets the seed that the other peers can use to replicate the token 
	 * generator sequence.
	 * 
	 * @return The seed used to initialise the TokenGenerator.
	 */
	public long getSeed();
}

/******************************************************************************
 * END OF FILE:     TokenGenerator.java
 *****************************************************************************/