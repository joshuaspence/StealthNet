/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        PRNGNonceGenerator.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     Implementation of a pseudo-random number generator (PRNG)
 * 					for nonce generation.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet.Security;

/* Import Libraries ********************************************************* */

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.codec.binary.Base64;

/* StealthNet.Security.PRNGNonceGenerator Class Definition ****************** */

/**
 * A psuedo-random number generator (PRNG) that accepts a seed value. Two
 * instances of this classes with the same seeds should produce the same
 * sequences of pseudo-random numbers. This class keeps track of pseudo-random
 * numbers that have been consumed, such that a peer receiving a packet is able
 * to check whether that packet is being replayed.
 * 
 * <p> A peer uses a single instance for the transmission of packets (which it
 * uses to generate nonces) and a single instance for the reception of packets
 * (which it uses to verify allowable nonces).
 * 
 * @author Joshua Spence
 * @see NonceGenerator
 */
public class PRNGNonceGenerator implements NonceGenerator {
	/** The pseudo-random number generator used to generate nonces. */
	private final SecureRandom prng;
	
	/** The number of bytes to generate for a nonce. */
	public static final int NONCE_BYTES = 8;
	
	/**
	 * The seed used to initialise for the {@link SecureRandom} pseudo-random
	 * number generator.
	 */
	private final byte[] seed;
	
	/**
	 * The set of all nonces that have been consumed. If a nonce in this set is
	 * received again, it should be discarded as this is indicative of a replay
	 * attack.
	 */
	private final Set<byte[]> consumedNonces;
	
	/** Constructor. */
	public PRNGNonceGenerator() {
		/* Use an unseeded pseudo-random number generator to create a seed. */
		final SecureRandom seedGenerator = new SecureRandom();
		seed = new byte[NONCE_BYTES];
		seedGenerator.nextBytes(seed);
		
		prng = new SecureRandom(seed);
		consumedNonces = new HashSet<byte[]>();
	}
	
	/**
	 * Constructor.
	 * 
	 * @param s Seed for the {@link SecureRandom} pseudo-random number
	 *        generator, assumed to be enoded in base-64.
	 * 
	 * @throws IllegalArgumentException
	 * @see Base64
	 */
	public PRNGNonceGenerator(byte[] s) throws IllegalArgumentException {
		s = Base64.decodeBase64(s);
		
		if (s.length != NONCE_BYTES)
			throw new IllegalArgumentException("Seed must be " + NONCE_BYTES + " bytes.");
		
		seed = new byte[s.length];
		System.arraycopy(s, 0, seed, 0, s.length);
		
		prng = new SecureRandom(seed);
		consumedNonces = new HashSet<byte[]>();
	}
	
	/**
	 * Get the next sequence number (nonce) from the psuedo-random number
	 * generator. Also consumes a sequence number.
	 * 
	 * @return The next sequence number (represented by a byte array of size
	 *         <code>NONCE_BYTES</code>).
	 */
	@Override
	public byte[] getNext() {
		final byte[] next = new byte[NONCE_BYTES];
		do
			prng.nextBytes(next);
		while (consumedNonces.contains(next));
		
		consumedNonces.add(next);
		return Base64.encodeBase64(next);
	}
	
	/**
	 * Check if a given nonce is allowed by checking whether it has been
	 * previously consumed.
	 * 
	 * @param nonce The nonce that was received.
	 * @return True if the received nonce has not been previously consumed.
	 *         False otherwise
	 */
	@Override
	public boolean isAllowed(byte[] nonce) {
		nonce = Base64.decodeBase64(nonce);
		
		if (consumedNonces.contains(nonce))
			return false;
		
		/* Consume the nonce. */
		consumedNonces.add(nonce);
		
		return true;
	}
	
	/**
	 * Gets the seed used for the {@link SecureRandom} pseudo-random number
	 * generator.
	 * 
	 * @return The seed used to initialise the {@link SecureRandom}
	 *         pseudo-random number generator, encoded in base-64.
	 */
	@Override
	public byte[] getSeed() {
		return Base64.encodeBase64(seed);
	}
}

/******************************************************************************
 * END OF FILE: PRNGNonceGenerator.java
 *****************************************************************************/
