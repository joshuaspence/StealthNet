/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie, Stephen Gould and Ryan Junee
 *
 * PACKAGE:         StealthNet
 * FILENAME:        CryptoCredit.java
 * AUTHORS:         Joshua Spence and James Dimitrios Moutafidis
 * DESCRIPTION:     Implementation of the StealthNet CryptoCredit class.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet;

/* Import Libraries ******************************************************** */

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Stack;

/* StealthNet.CryptoCredit Class Definition ******************************** */

/**
 * TODO
 * 
 * @author Joshua Spence
 * @author James Dimitrios Moutafidis
 */
public class CryptoCredit {
	/** Constants. */
	private static final String HASH_ALGORITHM = "MD5";
	
	/** Stack to store the hash chain. */
	private static final Stack<byte[]> hashChain = new Stack<byte[]>();
	
	/** The starting credit of the hash chain **/
	private int startingCredit = 0;
	
	/** The amount of credits **/
	private int cryptoCredits = 0;
	
	/**
	 * Constructor. Calls the function to generate a new hash chain.
	 * 
	 * @param c An integer indicating the starting amount of credits.
	 */
	public CryptoCredit(final int c) {
		cryptoCredits = c;
		createNewHashChain();
	}
	
	/**
	 * Create a new hash chain. The old chain is deleted and a new one is
	 * generated.
	 */
	public void createNewHashChain() {
		final MessageDigest mdb;
		try {
			mdb = MessageDigest.getInstance(HASH_ALGORITHM);
		} catch (final Exception e) {
			System.err.println("Unable to create hash chain.");
			return;
		}
		final SecureRandom secureRandom = new SecureRandom();
		startingCredit = secureRandom.nextInt();
		
		final String startingCreditString = startingCredit + "";
		
		byte[] creditHash = mdb.digest(startingCreditString.getBytes());
		hashChain.clear();
		hashChain.push(creditHash);
		
		for (int i = 1; i < cryptoCredits; i++) {
			creditHash = mdb.digest(hashChain.peek().toString().getBytes());
			hashChain.push(creditHash);
		}
		
		cryptoCredits = hashChain.size();
	}
	
	/**
	 * Returns the starting credit of the hash chain.
	 * 
	 * @return The starting credit.
	 */
	public int getStartingCredit() {
		return startingCredit;
	}
	
	/**
	 * Returns the entire hash chain.
	 * 
	 * @return The stack of hashes.
	 */
	public Stack<byte[]> getHashChain() {
		return hashChain;
	}
	
	/**
	 * Spends a credit from the hash chain. If the chain is not empty, the top
	 * credit is removed from the stack and the hash of the credit is returned.
	 * If the chain is empty, the function returns null.
	 * 
	 * @return The top credit in the stack.
	 */
	public byte[] spend() {
		byte[] topCredit = null;
		if (!hashChain.isEmpty()) {
			topCredit = hashChain.pop();
			cryptoCredits--;
		}
		return topCredit;
	}
}

/******************************************************************************
 * END OF FILE: CryptoCredit.java
 *****************************************************************************/
