/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        DiffieHellmanKeyExchange.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     Implementation of Diffie-Hellman key exchange for ELEC5616
 *                  programming assignment.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet.Security;

/* Import Libraries ********************************************************* */

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

/* StealthNet.Security.DiffieHellmanKeyExchange Class Definition ************ */

/**
 * This class implements the Diffie-Hellman key exchange algorithm.
 * 
 * Diffie-Hellman key exchanges involves combining your private key with your
 * partner's public key to generate a number. The peer does the same with its
 * private key and our public key. Through the magic of Diffie-Hellman we both
 * come up with the same number. This number is secret (discounting MITM
 * attacks) and hence called the shared secret. It has the same length as the
 * modulus, e.g. 512 or 1024 bit.
 * 
 * The thing to note is that the shared secret is constant for two partners with
 * constant private keys. This is often not what we want, which is why it is
 * generally a good idea to create a new private key for each session.
 * Generating a private key involves one modular exponentiation assuming
 * suitable Diffie-Hellman parameters are available.
 * 
 * 
 * The protocol depends on the discrete logarithm problem for its security. It
 * assumes that it is computationally infeasible to calculate the shared secret
 * key 'k = generator^ab mod prime' given the two public values 'generator^a mod
 * prime' and 'generator^b mod prime' when the prime is sufficiently large.
 * Maurer has shown that breaking the Diffie-Hellman protocol is equivalent to
 * computing discrete logarithms under certain assumptions.
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
public class DiffieHellmanKeyExchange implements KeyExchange {
	/**
	 * Group parameters.
	 * 
	 * Parameter <pre>prime</pre> is a prime number and parameter
	 * <pre>generator</pre> is an integer less than <pre>prime</pre>, with the
	 * following property: for every number <pre>n</pre> between <pre>1</pre>
	 * and <pre>prime - 1</pre> inclusive, there is a power <pre>k</pre> of
	 * <pre>generator</pre> such that <pre>n = generator^k mod prime</pre>.
	 */
	private final BigInteger prime;
	private final BigInteger generator;
	
	/**
	 * <em>NOTE:</em> It is preferable for security, though not necessary, that
	 * base be a generator with respect to prime. Otherwise, the pool of
	 * possible keys is reduced, leaving the system more vulnerable to attack.
	 */
	
	/** Our private key. */
	private final PrivateKey privateKey;
	
	/** Public component of our key (= `generator^random mod prime'). */
	private final BigInteger publicValue;
	
	/** String constants. */
	private static final String KEY_ALGORITHM = "DiffieHellman";
	private static final String SECRET_KEY_ALGORITHM = "TlsPremasterSecret";
	
	/**
	 * Generate a Diffie-Hellman keypair of the specified size.
	 * 
	 * @param keyLength Number of bits for the key.
	 * @param random A SecureRandom number.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public DiffieHellmanKeyExchange(final int keyLength, final SecureRandom random) throws NoSuchAlgorithmException, InvalidKeySpecException {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		kpg.initialize(keyLength, random);
		
		final KeyPair kp = kpg.generateKeyPair();
		final KeyFactory kfactory = KeyFactory.getInstance(KEY_ALGORITHM);
		
		final DHPublicKeySpec spec = kfactory.getKeySpec(kp.getPublic(), DHPublicKeySpec.class);
		
		privateKey = kp.getPrivate();
		publicValue = spec.getY();
		prime = spec.getP();
		generator = spec.getG();
	}
	
	/**
	 * Generate a Diffie-Hellman key pair using the specified parameters.
	 * 
	 * @param prime The Diffie-Hellman large prime 'p'.
	 * @param generator The Diffie-Hellman generator 'g'.
	 * @param random A SecureRandom number.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeySpecException
	 */
	DiffieHellmanKeyExchange(final BigInteger prime, final BigInteger generator, final SecureRandom random) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException {
		this.prime = prime;
		this.generator = generator;
		
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		final DHParameterSpec params = new DHParameterSpec(this.prime, this.generator);
		
		kpg.initialize(params, random);
		final KeyPair kp = kpg.generateKeyPair();
		final DHPublicKeySpec spec = getDHPublicKeySpec(kp.getPublic());
		
		privateKey = kp.getPrivate();
		publicValue = spec.getY();
	}
	
	/**
	 * Returns the DHPublicKeySpec corresponding to a given PublicKey.
	 * 
	 * @param key The given PublicKey.
	 * @return The DHPublicKeySpec corresponding to a given PublicKey.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static DHPublicKeySpec getDHPublicKeySpec(final PublicKey key) throws NoSuchAlgorithmException, InvalidKeySpecException {
		if (key instanceof DHPublicKey) {
			final DHPublicKey dhKey = (DHPublicKey) key;
			final DHParameterSpec params = dhKey.getParams();
			return new DHPublicKeySpec(dhKey.getY(), params.getP(), params.getG());
		}
		
		final KeyFactory kfactory = KeyFactory.getInstance(KEY_ALGORITHM);
		return kfactory.getKeySpec(key, DHPublicKeySpec.class);
	}
	
	/**
	 * Gets the Diffie-Hellman prime number parameter.
	 * 
	 * @return The Diffie-Hellman prime number.
	 */
	public BigInteger getPrime() {
		return prime;
	}
	
	/**
	 * Gets the Diffie-Hellman generator parameter.
	 * 
	 * @return The Diffie-Hellman generator.
	 */
	public BigInteger getGenerator() {
		return generator;
	}
	
	/**
	 * Gets the public key of this end of the key exchange.
	 * 
	 * @return The public key of this end of the key exchange.
	 */
	@Override
	public BigInteger getPublicKey() {
		return publicValue;
	}
	
	/**
	 * Get the secret data that has been agreed on through Diffie-Hellman key
	 * agreement protocol. Note that in the two party protocol, if the peer keys
	 * are already known, no other data needs to be sent in order to agree on a
	 * secret. That is, a secured message may be sent without any mandatory
	 * round-trip overheads.
	 * 
	 * It is illegal to call this member function if the private key has not
	 * been set (or generated).
	 * 
	 * @param peerPublicValue The peer's public key.
	 * @return The secret, which is an unsigned big-endian integer the same size
	 *         as the Diffie-Hellman modulus.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IllegalStateException
	 * @throws InvalidKeyException
	 */
	@Override
	public SecretKey getSharedSecret(final BigInteger peerPublicValue) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
		final KeyFactory kf = KeyFactory.getInstance(KEY_ALGORITHM);
		final KeyAgreement ka = KeyAgreement.getInstance(KEY_ALGORITHM);
		
		final DHPublicKeySpec spec = new DHPublicKeySpec(peerPublicValue, prime, generator);
		final PublicKey publicKey = kf.generatePublic(spec);
		
		ka.init(privateKey);
		ka.doPhase(publicKey, true);
		return ka.generateSecret(SECRET_KEY_ALGORITHM);
	}
}

/******************************************************************************
 * END OF FILE: DiffieHellmanKeyExchange.java
 *****************************************************************************/
