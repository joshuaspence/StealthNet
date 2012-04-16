/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie and Stephen Gould
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        MessageAuthenticationCode.java
 * AUTHORS:         Joshua Spence and Ahmad Al Mutawa
 * DESCRIPTION:     An interface to provide StealthNet with Message 
 * 					Authentication Codes (MACs).
 * VERSION:         1.0
 *
 *****************************************************************************/

package StealthNet.Security;

/* Import Libraries **********************************************************/

/* MessageAuthenticationCode Interface Definition ****************************/

/**
 * Calculates and verifies packet Message Authentication Codes (MACs). This is 
 * used to ensure packet integrity between peers.
 * 
 * @author Joshua Spence
 */
public interface MessageAuthenticationCode {	
	/**
	 * Calculates the MAC for a given message.
	 * 
	 * @param message The message to calculate the MAC for.
	 * @return The digest of the given message (in base-64 encoding).
	 */
	public String createMAC(String message);

	
	/**
	 * Verifies a given message against a given MAC digest.
	 * 
	 * @param message The message to check.
	 * @param mac The given MAC digest (in base-64 encoding).
	 * 
	 * @return True if the message matches the given MAC digest, otherwise 
	 * false.
	 */
	public boolean verifyMAC(String message, byte[] mac);
}

/******************************************************************************
 * END OF FILE:     MessageAuthenticationCode.java
 *****************************************************************************/