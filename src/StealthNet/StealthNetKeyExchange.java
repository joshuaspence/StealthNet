package StealthNet;

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

/**
 * This class implements the Diffie-Hellman key exchange algorithm. 
 * Diffie-Hellman key exchanges involves combining your private key with your 
 * partners public key to generate a number. The peer does the same with its 
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
 *  - If we are server, call StealthNetKeyExchange(keyLength,random). This 
 *    generates an ephemeral keypair of the request length.
 *  - If we are client, call StealthNetKeyExchange(modulus, base, random). This
 *    generates an ephemeral keypair using the parameters specified by the 
 *    server.
 *  - Send parameters and public value to remote peer.
 *  - Receive peers ephemeral public key
 *  - Call getAgreedSecret() to calculate the shared secret
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
 * @author Joshua Spence
 */
public class StealthNetKeyExchange {
	/** Length of the key (in bits). */
	public final static int NUM_BITS = 1024;
	
	/** Group parameters */
	// {
	private final BigInteger prime;		// prime modulus (q)
	private final BigInteger base;		// base (alpha)
	// }
	
	/**
	 * It is preferable for security, though not necessary, that base be a 
	 * generator with respect to prime. Otherwise, the pool of possible keys is 
	 * reduced, leaving the system more vulnerable to attack.
	 */
	
	/** Our private key. */
	private PrivateKey privateKey;
	
	/** Public component of our key. */
	private BigInteger publicValue;
	
	/** 
	 * Generate a Diffie-Hellman keypair of the specified size. 
	 * 
	 * @param keyLength Number of bits for the key.
	 * @param random A SecureRandom number.
	 * 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public StealthNetKeyExchange(int keyLength, SecureRandom random) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
		kpg.initialize(keyLength, random);
		KeyPair kp = kpg.generateKeyPair();
		KeyFactory kfactory = KeyFactory.getInstance("DiffieHellman");
		DHPublicKeySpec spec = (DHPublicKeySpec) kfactory.getKeySpec(kp.getPublic(), DHPublicKeySpec.class);
		
		privateKey = kp.getPrivate();
		publicValue = spec.getY();
		prime = spec.getP();
		base = spec.getG();
	}
	
	/**
	 * Generate a Diffie-Hellman keypair using the specified parameters.
	 *
	 * @param prime The Diffie-Hellman large prime q.
	 * @param base The Diffie-Hellman base alpha.
	 * 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeySpecException 
	 */
	StealthNetKeyExchange(BigInteger prime, BigInteger base, SecureRandom random) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException {
		this.prime = prime;
		this.base = base;
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
		DHParameterSpec params = new DHParameterSpec(prime, base);
		kpg.initialize(params, random);
		KeyPair kp = kpg.generateKeyPair();
		DHPublicKeySpec spec = getDHPublicKeySpec(kp.getPublic());
		
		privateKey = kp.getPrivate();
		publicValue = spec.getY();
	}
	
	private static DHPublicKeySpec getDHPublicKeySpec(PublicKey key) throws NoSuchAlgorithmException, InvalidKeySpecException {
		if (key instanceof DHPublicKey) {
			DHPublicKey dhKey = (DHPublicKey) key;
			DHParameterSpec params = dhKey.getParams();
			return new DHPublicKeySpec(dhKey.getY(), params.getP(), params.getG());
		}
		
		KeyFactory kfactory = KeyFactory.getInstance("DiffieHellman");
		return (DHPublicKeySpec) kfactory.getKeySpec(key, DHPublicKeySpec.class);
	}

	/** @return Returns the Diffie-Hellman modulus. */
	public BigInteger getPrime() {
		return prime;
	}
	
	/** @return Returns the Diffie-Hellman base (generator). */
	public BigInteger getBase() {
		return base;
	}
	
	/** @return Gets the public key of this end of the key exchange. */
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
	 SecretKey getSharedSecret(BigInteger peerPublicValue) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalStateException {
		 KeyFactory kf = KeyFactory.getInstance("DiffieHellman");
		 DHPublicKeySpec spec = new DHPublicKeySpec(peerPublicValue, prime, base);
		 PublicKey publicKey = kf.generatePublic(spec);
		 KeyAgreement ka = KeyAgreement.getInstance("DiffieHellman");
		 
		 ka.init(privateKey);
		 ka.doPhase(publicKey, true);
		 return ka.generateSecret("TlsPremasterSecret");
	 }
}