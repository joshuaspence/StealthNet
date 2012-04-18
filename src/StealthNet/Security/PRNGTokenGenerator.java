/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
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

/* StealthNet.Security.PRNGTokenGenerator Class Definition *******************/

/**
 * A psuedo-random number generator (PRNG) that accepts a seed value. Two 
 * instances of this classes with the same seeds should produce the same 
 * sequences of pseudo-random numbers. This class keeps tracked of pseudo-random
 * numbers that have been consumed, such that a peer receiving a packet is able
 * to check whether that packet is being replayed.
 * 
 * A peer uses a single instance for the transmission of packets (which it uses
 * to generate token numbers) and a single instance for the reception of 
 * packets (which it uses to verify allowable token numbers).
 * 
 * @author Joshua Spence
 */
public class PRNGTokenGenerator implements TokenGenerator {
	/** The PRNG. */
	private final Random prng;
	
	/** The seed for the PRNG. */
	private final long seed;
	
	/** 
	 * The set of all consumed tokens. If a token in this set is received again,
	 * it should be discarded.
	 */
	private final Set<Long> consumedTokens; 
	
	/** Constructor. */
	public PRNGTokenGenerator() {
		/** Use an unseeded pseudo-random number generator to create a seed, */
		final Random seedGenerator = new Random();
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
		Long next;
		do {
			next = prng.nextLong();
		} while (consumedTokens.contains(new Long(next)));
		
		consumedTokens.add(new Long(next));
		return next;
	}
	
	/** 
	 * Check if a given token number is allowed by checking whether it has been
	 * previously consumed.
	 * 
	 * @param tok The sequence number that was received.
	 * @return True if the received token number has not been previously 
	 * consumed. False otherwise
	 */
	public boolean isAllowed(long tok) {
		Long lTok = new Long(tok);
		
		if (consumedTokens.contains(lTok))
			return false;
		
		/** Consume the token. */
		consumedTokens.add(lTok);
		
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