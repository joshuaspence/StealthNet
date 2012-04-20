/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        PRNGNonceGenerator.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     Implementation of a pseudo-random number generator (PRNG)
 * 					for nonce generation.
 * VERSION:         1.0
 *
 *****************************************************************************/

package StealthNet.Security;

/* Import Libraries **********************************************************/

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.codec.binary.Base64;

/* StealthNet.Security.PRNGNonceGenerator Class Definition *******************/

/**
 * A psuedo-random number generator (PRNG) that accepts a seed value. Two 
 * instances of this classes with the same seeds should produce the same 
 * sequences of pseudo-random numbers. This class keeps track of pseudo-random
 * numbers that have been consumed, such that a peer receiving a packet is able
 * to check whether that packet is being replayed.
 * 
 * A peer uses a single instance for the transmission of packets (which it uses
 * to generate nonces) and a single instance for the reception of packets (which
 * it uses to verify allowable nonces).
 * 
 * @author Joshua Spence
 */
public class PRNGNonceGenerator implements NonceGenerator {
	/** The PRNG. */
	private final SecureRandom prng;
	
	/** The seed for the PRNG. */
	public static final int NONCE_BYTES = 8;
	private final byte[] seed;
	
	/** 
	 * The set of all consumed nonces. If a nonce in this set is received again,
	 * it should be discarded.
	 */
	private final Set<byte[]> consumedNonces; 
	
	/** Constructor. */
	public PRNGNonceGenerator() {
		/** Use an unseeded pseudo-random number generator to create a seed, */
		final SecureRandom seedGenerator = new SecureRandom();
		this.seed = new byte[NONCE_BYTES]; 
		seedGenerator.nextBytes(this.seed);
		
		this.prng = new SecureRandom(this.seed);
		this.consumedNonces = new HashSet<byte[]>();
	}
	
	/**
	 * Constructor.
	 * 
	 * @param s Seed for the PRNG.
	 * 
	 * @throws IllegalArgumentException
	 */
	public PRNGNonceGenerator(byte[] s) throws IllegalArgumentException {
		s = Base64.decodeBase64(s);
		
		if (s.length != NONCE_BYTES)
			throw new IllegalArgumentException("Seed must be " + NONCE_BYTES + " bytes.");
		
		this.seed = new byte[s.length];
		System.arraycopy(s, 0, this.seed, 0, s.length);
		
		this.prng = new SecureRandom(this.seed);
		this.consumedNonces = new HashSet<byte[]>();
	}
	
	 /** 
	  * Get the next sequence number from the PRNG. Also consumes a sequence 
	  * number.
	  * 
	  * @return The next sequence number (represented by a byte array).
	  */
	public byte[] getNext() {
		byte[] next = new byte[NONCE_BYTES];
		do {
			prng.nextBytes(next);
		} while (consumedNonces.contains(next));
		
		consumedNonces.add(next);
		return Base64.encodeBase64(next);
	}
	
	/** 
	 * Check if a given nonce is allowed by checking whether it has been
	 * previously consumed.
	 * 
	 * @param nonce The nonce that was received.
	 * @return True if the received nonce has not been previously consumed.  
	 * False otherwise
	 */
	public boolean isAllowed(byte[] nonce) {
		nonce = Base64.decodeBase64(nonce);
		
		if (consumedNonces.contains(nonce))
			return false;
		
		/** Consume the nonce. */
		consumedNonces.add(nonce);
		
		return true;
	}
	
	/**
	 * Gets the seed used for the PRNG.
	 * 
	 * @return The seed used to initialise the PRNG.
	 */
	public byte[] getSeed() {
		return Base64.encodeBase64(seed);
	}
}

/******************************************************************************
 * END OF FILE:     PRNGNonceGenerator.java
 *****************************************************************************/