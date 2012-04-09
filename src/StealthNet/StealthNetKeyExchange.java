/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie and Stephen Gould
 *
 * PROJECT:         StealthNet
 * FILENAME:        StealthNetKeyExchange.java
 * AUTHORS:         Joshua Spence and Ahmad Al Mutawa
 * DESCRIPTION:     Implementation of Diffie-Hellman key exchange for ELEC5616
 *                  programming assignment.
 * VERSION:         1.0
 *
 *****************************************************************************/

package StealthNet;

/* Import Libraries **********************************************************/

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

/* StealthNetKeyExchange Class Definition *************************************/

/**
 * This class implements the Diffie-Hellman key exchange algorithm. 
 * 
 * Diffie-Hellman key exchanges involves combining your private key with your 
 * partner's public key to generate a number. The peer does the same with its 
 * private key and our public key. Through the magic of Diffie-Hellman we both 
 * come up with the same number. This number is secret (discounting MITM 
 * attacks) and hence called the shared secret. It has the same length as the 
 * modulus, e.g. 512 or 1024 bit. Man-in-the-middle attacks are typically 
 * countered by an independent authentication step using certificates (RSA, DSA,
 * etc.).
 *
 * The thing to note is that the shared secret is constant for two partners with
 * constant private keys. This is often not what we want, which is why it is
 * generally a good idea to create a new private key for each session.
 * Generating a private key involves one modular exponentiation assuming 
 * suitable Diffie-Hellman parameters are available.
 *
 * General usage of this class:
 *  - If we are server, call StealthNetKeyExchange(keyLength, random). This 
 *    generates an ephemeral keypair of the request length.
 *  - If we are client, call StealthNetKeyExchange(modulus, base, random). This
 *    generates an ephemeral keypair using the parameters specified by the 
 *    server.
 *  - Send parameters and public value to remote peer.
 *  - Receive peers ephemeral public key
 *  - Call getAgreedSecret() to calculate the shared secret.
 *
 * In TLS the server chooses the parameter values itself, the client must use
 * those sent to it by the server.
 *
 * The use of ephemeral keys as described above also achieves what is called
 * "forward secrecy". This means that even if the authentication keys are
 * broken at a later date, the shared secret remains secure. The session is
 * compromised only if the authentication keys are already broken at the time
 * the key exchange takes place and an active MITM attack is used. This is in
 * contrast to straightforward encrypting RSA key exchanges.
 * 
 * The protocol depends on the discrete logarithm problem for its security. It 
 * assumes that it is computationally infeasible to calculate the shared secret 
 * key 'k = generator^ab mod prime' given the two public values 
 * 'generator^a mod prime' and 'generator^b mod prime' when the prime is 
 * sufficiently large. Maurer has shown that breaking the Diffie-Hellman 
 * protocol is equivalent to computing discrete logarithms under certain 
 * assumptions.
 * 
 * The Diffie-Hellman key exchange is vulnerable to a man-in-the-middle attack. 
 * In this attack, an opponent Carol intercepts Alice's public value and sends 
 * her own public value to Bob. When Bob transmits his public value, Carol 
 * substitutes it with her own and sends it to Alice. Carol and Alice thus agree
 * on one shared key and Carol and Bob agree on another shared key. After this 
 * exchange, Carol simply decrypts any messages sent out by Alice or Bob, and 
 * then reads and possibly modifies them before re-encrypting with the 
 * appropriate key and transmitting them to the other party. This vulnerability 
 * is present because Diffie-Hellman key exchange does not authenticate the 
 * participants. Possible solutions include the use of digital signatures and 
 * other protocol variants.
 *
 * @author Joshua Spence
 */
public class StealthNetKeyExchange {
	/** Length of the key (in bits). */
	public final static int NUM_BITS = 1024;
	
	/** Test Diffie-Hellman prime and generator parameters? */
	private static final boolean TEST_PARAMETERS = true;
	
	/** 
	 * Group parameters.
	 *
	 * Parameter 'prime' is a prime number and parameter 'generator' is an 
	 * integer less than 'prime', with the following property: for every number 
	 * 'n' between '1' and 'prime - 1' inclusive, there is a power 'k' of 
	 * 'generator' such that 'n = generator^k mod prime'.
	 */
	// {
	private final BigInteger prime;
	private final BigInteger generator;
	// }
	
	/**
	 * It is preferable for security, though not necessary, that base be a 
	 * generator with respect to prime. Otherwise, the pool of possible keys is 
	 * reduced, leaving the system more vulnerable to attack.
	 */
	
	/** Our private key. */
	private final PrivateKey privateKey;
	
	/** Public component of our key (= generator^random mod prime). */
	private final BigInteger publicValue;
	
	/** 
	 * Generate a Diffie-Hellman keypair of the specified size. 
	 * 
	 * @param keyLength Number of bits for the key.
	 * @param random A SecureRandom number.
	 * 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws InvalidDHParameterException 
	 */
	public StealthNetKeyExchange(int keyLength, SecureRandom random) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidDHParameterException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
		kpg.initialize(keyLength, random);
		KeyPair kp = kpg.generateKeyPair();
		KeyFactory kfactory = KeyFactory.getInstance("DiffieHellman");
		DHPublicKeySpec spec = (DHPublicKeySpec) kfactory.getKeySpec(kp.getPublic(), DHPublicKeySpec.class);
		
		this.privateKey = kp.getPrivate();
		this.publicValue = spec.getY();
		this.prime = spec.getP();
		this.generator = spec.getG();
		
		try {
			if (TEST_PARAMETERS)
				checkParameters(this.prime, this.generator);
		} catch (InvalidDHParameterException e) {
			throw new InvalidDHParameterException("Invalid Diffie-Hellman parameters. " + e.getMessage());
		}
	}
	
	/**
	 * Generate a Diffie-Hellman keypair using the specified parameters.
	 *
	 * @param prime The Diffie-Hellman large prime 'p'.
	 * @param generator The Diffie-Hellman generator 'g'.
	 * @param random A SecureRandom number.
	 * 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeySpecException 
	 */
	StealthNetKeyExchange(BigInteger prime, BigInteger generator, SecureRandom random) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException, InvalidDHParameterException {
		try {
			if (TEST_PARAMETERS)
				checkParameters(prime, generator);
		} catch (InvalidDHParameterException e) {
			throw new InvalidDHParameterException("Invalid Diffie-Hellman parameters. " + e.getMessage());
		}
		
		this.prime = prime;
		this.generator = generator;
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
		DHParameterSpec params = new DHParameterSpec(this.prime, this.generator);
		kpg.initialize(params, random);
		KeyPair kp = kpg.generateKeyPair();
		DHPublicKeySpec spec = getDHPublicKeySpec(kp.getPublic());
		
		privateKey = kp.getPrivate();
		publicValue = spec.getY();
	}
	
	/**
	 * Returns the DHPublicKeySpec corresponding to a given PublicKey.
	 * 
	 * @param key The given PublicKey.
	 * @return Returns the DHPublicKeySpec corresponding to a given PublicKey.
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static DHPublicKeySpec getDHPublicKeySpec(PublicKey key) throws NoSuchAlgorithmException, InvalidKeySpecException {
		if (key instanceof DHPublicKey) {
			DHPublicKey dhKey = (DHPublicKey) key;
			DHParameterSpec params = dhKey.getParams();
			return new DHPublicKeySpec(dhKey.getY(), params.getP(), params.getG());
		}
		
		KeyFactory kfactory = KeyFactory.getInstance("DiffieHellman");
		return (DHPublicKeySpec) kfactory.getKeySpec(key, DHPublicKeySpec.class);
	}

	/** 
	 * Returns the Diffie-Hellman modulus.
	 * 
	 * @return Returns the Diffie-Hellman prime number.
	 */
	public BigInteger getPrime() {
		return prime;
	}
	
	/** 
	 * Returns the Diffie-Hellman base (generator).
	 * 
	 * @return Returns the Diffie-Hellman base (generator).
	 */
	public BigInteger getGenerator() {
		return generator;
	}
	
	/** 
	 * Gets the public key of this end of the key exchange.
	 * 
	 * @return Gets the public key of this end of the key exchange.
	 */
	public BigInteger getPublicKey() {
		return publicValue;
	}
	
	/**
	 * Get the secret data that has been agreed on through Diffie-Hellman key
	 * agreement protocol.  Note that in the two party protocol, if the peer
	 * keys are already known, no other data needs to be sent in order to agree
	 * on a secret. That is, a secured message may be sent without any mandatory
	 * round-trip overheads.
	 *
	 * It is illegal to call this member function if the private key has not 
	 * been set (or generated).
	 *
	 * @param peerPublicKey The peer's public key.
	 * @return The secret, which is an unsigned big-endian integer the same size
	 * as the Diffie-Hellman modulus.
	 * 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws IllegalStateException 
	 * @throws InvalidKeyException 
	 */
	 public SecretKey getSharedSecret(BigInteger peerPublicValue) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalStateException {
		 KeyFactory kf = KeyFactory.getInstance("DiffieHellman");
		 DHPublicKeySpec spec = new DHPublicKeySpec(peerPublicValue, prime, generator);
		 PublicKey publicKey = kf.generatePublic(spec);
		 KeyAgreement ka = KeyAgreement.getInstance("DiffieHellman");
		 
		 ka.init(privateKey);
		 ka.doPhase(publicKey, true);
		 return ka.generateSecret("TlsPremasterSecret");
	 }
	 
	 /**
	  * Checks that the parameters for the key exchange meet all of the given
	  * mathematical criteria.
	  * 
	  * @param p The specified prime number.
	  * @param g The specified generator.
	  * @return True if all criteria are met, otherwise false.
	  * 
	  * @throws InvalidDHParameterException 
	  */
	 private static boolean checkParameters(BigInteger p, BigInteger g) throws InvalidDHParameterException {
		 /** Make sure 'g < p'. */
		 if (g.compareTo(p) >= 0)
			 throw new InvalidDHParameterException("'Generator' number must be less than 'prime' number.");
		 
		 /** Make sure 'prime' is really a prime number. */
		 if (!isPrime(p))
			 throw new InvalidDHParameterException("'Prime' number must be a prime number.");
		 
		 /** 
		  * Make sure the following rule can be satisified: for every number 'n' 
		  * between '1' and 'prime - 1' inclusive, there is a power 'k' of 
		  * 'generator' such that 'n = generator^k mod prime'.
		  */
		 if (!isGenerator(p, g))
			 throw new InvalidDHParameterException("'Generator' number must be a generator of 'prime' number.");
		 
		 return true;
	 }
	 
	 /**
	  * A simple method to test is a given number is prime. Not the most 
	  * efficient method for primality testing, but this method is really only 
	  * for test purposes.
	  * 
	  * @param p The number to test for primality.
	  * @return True if the parameter is prime, otherwise false.
	  */
	 private static boolean isPrime(BigInteger p) {
		 for (BigInteger i = BigInteger.valueOf(2); (i.compareTo(p) < 0); i = i.add(BigInteger.ONE)) {
			  if (p.mod(i).compareTo(BigInteger.ZERO) == 0)
				  return false;
		  }
		 
		 return true;
	 }
	 
	 /** 
	  * A simple method to test that a given number 'g' is a generator of a 
	  * given prime 'p' (NOTE: does not test if 'p' is prime). This method is 
	  * not very efficient, but is only really used for testing purposes.
	  * 
	  * @param p The given prime number.
	  * @param g The number to test if is a generator of 'p'.
	  * @return True is 'g' is a generator of 'p', otherwise false.
	  */
	 private static boolean isGenerator(BigInteger p, BigInteger g) {
		 for (BigInteger n = BigInteger.ONE; (n.compareTo(p) < 0); n = n.add(BigInteger.ONE)) {
			 boolean found_k =  false;
			 
			 for (int k = 0; k <= Integer.MAX_VALUE; k++) {
				 if (g.pow(k).mod(p) == n) {
					 found_k = true;
					 break;
				 }
			 }
			 
			 if (!found_k)
				 return false;
		 }
		 
		 return true;
	 }
}

/**
 * An exception to be thrown if invalid 'prime' and 'generator' parameters are
 * specified when creating a StealthNetKeyExchange.
 * 
 * @author Joshua Spence
 */
class InvalidDHParameterException extends Exception {
	private static final long serialVersionUID = 1L;
  
	public InvalidDHParameterException(String msg) {
		super(msg);
	}
}

/******************************************************************************
 * END OF FILE:     StealthNetKeyExchange.java
 *****************************************************************************/