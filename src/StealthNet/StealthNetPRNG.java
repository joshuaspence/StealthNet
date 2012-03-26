package StealthNet;

import java.util.Random;

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
public class StealthNetPRNG {
	/** 
	 * Set to true in build.xml to output debug messages for this class. 
	 * Alternatively, use the argument `-Ddebug.StealthNetPRNG=true' at the 
	 * command line. 
	 */
	@SuppressWarnings("unused")
	private static final boolean DEBUG = (System.getProperty("debug.StealthNetPRNG", "false").equals("true"));
	
	/** The PRNG. */
	private final Random prng;
	
	/** The seed for the PRNG. */
	private final long seed;
	
	/** The next sequence number. */
	Integer next;
	
	/**
	 * Constructor.
	 * 
	 * @param s Seed for the PRNG.
	 */
	public StealthNetPRNG(long s) {
		prng = new Random(s);
		seed = s;
		next = null;
	}
	
	 /** 
	  * Get the next sequence number from the PRNG. Also consumes a sequence 
	  * number.
	  * 
	  * @return The next sequence number.
	  */
	public int getNextSequenceNumber() {
		next = prng.nextInt();
		return next;
	}
	
	/** 
	 * Check if a given sequence number is the expected sequence number by 
	 * comparing it to the PRNG's value. 
	 * 
	 * @param seq The sequence number that was received.
	 * @return True if the received sequence number matches the expected
	 * sequence number, false otherwise.
	 */
	public boolean isExpectedSequenceNumber(int seq) {
		if (next == null) 
			next = getNextSequenceNumber();
			
		if (seq == next.intValue()) {
			next = getNextSequenceNumber();
			return true;
		}
			
		return false;
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
