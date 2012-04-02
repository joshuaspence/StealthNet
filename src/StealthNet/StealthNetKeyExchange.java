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
 * D-H means combining your private key with your partners public key to
 * generate a number. The peer does the same with its private key and our
 * public key. Through the magic of Diffie-Hellman we both come up with the
 * same number. This number is secret (discounting MITM attacks) and hence
 * called the shared secret. It has the same length as the modulus, e.g. 512
 * or 1024 bit. Man-in-the-middle attacks are typically countered by an
 * independent authentication step using certificates (RSA, DSA, etc.).
 *
 * The thing to note is that the shared secret is constant for two partners
 * with constant private keys. This is often not what we want, which is why
 * it is generally a good idea to create a new private key for each session.
 * Generating a private key involves one modular exponentiation assuming
 * suitable D-H parameters are available.
 *
 * General usage of this class (TLS DHE case):
 *  . if we are server, call DHCrypt(keyLength,random). This generates
 *    an ephemeral keypair of the request length.
 *  . if we are client, call DHCrypt(modulus, base, random). This
 *    generates an ephemeral keypair using the parameters specified by the server.
 *  . send parameters and public value to remote peer
 *  . receive peers ephemeral public key
 *  . call getAgreedSecret() to calculate the shared secret
 *
 * In TLS the server chooses the parameter values itself, the client must use
 * those sent to it by the server.
 *
 * The use of ephemeral keys as described above also achieves what is called
 * "forward secrecy". This means that even if the authentication keys are
 * broken at a later date, the shared secret remains secure. The session is
 * compromised only if the authentication keys are already broken at the
 * time the key exchange takes place and an active MITM attack is used.
 * This is in contrast to straightforward encrypting RSA key exchanges.
 *
 * @author Joshua Spence
 */
public class StealthNetKeyExchange {	
	/* Group parameters */
	private final BigInteger modulus;	// prime modulus
	private final BigInteger base;		// generator
	
	/* Our private key */
	private PrivateKey privateKey;
	
	/* Public component of our key */
	private BigInteger publicValue;
	
	/** 
	 * Generate a Diffie-Hellman keypair of the specified size. 
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
		modulus = spec.getP();
		base = spec.getG();
	}
	
	/**
	 * Generate a Diffie-Hellman keypair using the specified parameters.
	 *
	 * @param modulus the Diffie-Hellman modulus P
	 * @param base the Diffie-Hellman base G
	 * 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeySpecException 
	 */
	StealthNetKeyExchange(BigInteger modulus, BigInteger base, SecureRandom random) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException {
		this.modulus = modulus;
		this.base = base;
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
		DHParameterSpec params = new DHParameterSpec(modulus, base);
		kpg.initialize(params, random);
		KeyPair kp = kpg.generateKeyPair();
		DHPublicKeySpec spec = getDHPublicKeySpec(kp.getPublic());
		
		privateKey = kp.getPrivate();
		publicValue = spec.getY();
	}
	
	static DHPublicKeySpec getDHPublicKeySpec(PublicKey key) throws NoSuchAlgorithmException, InvalidKeySpecException {
		if (key instanceof DHPublicKey) {
			DHPublicKey dhKey = (DHPublicKey) key;
			DHParameterSpec params = dhKey.getParams();
			return new DHPublicKeySpec(dhKey.getY(), params.getP(), params.getG());
		}
		
		KeyFactory kfactory = KeyFactory.getInstance("DiffieHellman");
		return (DHPublicKeySpec) kfactory.getKeySpec(key, DHPublicKeySpec.class);
	}

	/** Returns the Diffie-Hellman modulus. */
	BigInteger getModulus() {
		return modulus;
	}
	
	/** Returns the Diffie-Hellman base (generator).  */
	BigInteger getBase() {
		return base;
	}
	
	/** Gets the public key of this end of the key exchange. */
	BigInteger getPublicKey() {
		return publicValue;
	}
	
	/**
	 * Get the secret data that has been agreed on through Diffie-Hellman
	 * key agreement protocol.  Note that in the two party protocol, if
	 * the peer keys are already known, no other data needs to be sent in
	 * order to agree on a secret.  That is, a secured message may be
	 * sent without any mandatory round-trip overheads.
	 *
	 * <P>It is illegal to call this member function if the private key
	 * has not been set (or generated).
	 *
	 * @param peerPublicKey the peer's public key.
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws IllegalStateException 
	 * @throws InvalidKeyException 
	 * @returns the secret, which is an unsigned big-endian integer
	 *  the same size as the Diffie-Hellman modulus.
	 */
	 SecretKey getAgreedSecret(BigInteger peerPublicValue) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalStateException {
		 KeyFactory kf = KeyFactory.getInstance("DiffieHellman");
		 DHPublicKeySpec spec = new DHPublicKeySpec(peerPublicValue, modulus, base);
		 PublicKey publicKey = kf.generatePublic(spec);
		 KeyAgreement ka = KeyAgreement.getInstance("DiffieHellman");
		 
		 ka.init(privateKey);
		 ka.doPhase(publicKey, true);
		 return ka.generateSecret("TlsPremasterSecret");
	 }
}