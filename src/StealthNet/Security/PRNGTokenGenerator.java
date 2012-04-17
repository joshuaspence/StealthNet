/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie and Stephen Gould
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        PRNGTokenGenerator.java
 * AUTHORS:         Joshua Spence and Ahmad Al Mutawa
 * DESCRIPTION:     Implementation of a pseudo-random number generator (PRNG)
 * 					for token generation.
 * VERSION:         1.0
 *
 *****************************************************************************/

package StealthNet.Security;

/* Import Libraries **********************************************************/

import java.util.HashSet;
import java.util.Random;
import java.util.Set;

/* PRNGTokenGenerator Class Definition ***************************************/

/**
 * A psuedo-random number generator (PRNG) that accepts a seed value. Two 
 * instances of this classes with the same seeds should produce the same 
 * sequences of pseudo-random numbers.
 * 
 * This is used to prevent message replay attacks because both parties should be
 * able to predict the next expected sequence number of a packet if they share 
 * the PRNG seed.
 * 
 * @author Joshua Spence
 */
public class PRNGTokenGenerator implements TokenGenerator {
	/** The PRNG. */
	private final Random prng;
	
	/** The seed for the PRNG. */
	private final long seed;
	
	private final Set<Long> consumedTokens; 
	
	/** Constructor. */
	public PRNGTokenGenerator() {
		Random seedGenerator = new Random();
		this.seed = seedGenerator.nextLong();
		
		this.prng = new Random(this.seed);
		
		this.consumedTokens = new HashSet<Long>();
	}
	
	/**
	 * Constructor.
	 * 
	 * @param s Seed for the PRNG.
	 */
	public PRNGTokenGenerator(long s) {
		this.prng = new Random(s);
		this.seed = s;
		
		this.consumedTokens = new HashSet<Long>();
	}
	
	 /** 
	  * Get the next sequence number from the PRNG. Also consumes a sequence 
	  * number.
	  * 
	  * @return The next sequence number.
	  */
	public long getNext() {
		return prng.nextLong();
	}
	
	/** 
	 * Check if a given sequence number is the expected sequence number by 
	 * comparing it to the PRNG's value. 
	 * 
	 * @param seq The sequence number that was received.
	 * @return True if the received sequence number matches the expected
	 * sequence number, false otherwise.
	 */
	public boolean isAllowed(long seq) {
		Long lSeq = new Long(seq);
		
		if (consumedTokens.contains(lSeq))
			return false;
		
		consumedTokens.add(lSeq);
		return true;
	}
	
	/**
	 * Gets the seed used for the PRNG.
	 * 
	 * @return The seed used to initialise the PRNG.
	 */
	public long getSeed() {
		return seed;
	}
}

/******************************************************************************
 * END OF FILE:     PRNGTokenGenerator.java
 *****************************************************************************/