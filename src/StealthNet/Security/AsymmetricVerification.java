/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        AsymmetricVerification.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     A base class for using public-private keys to sign and 
 * 					verify data.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet.Security;

/* Import Libraries ******************************************************** */

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

/* StealthNet.Security.AsymmetricVerification Class Definition ************* */

/**
 * A base class to provide public-private key (asymmetric) verification.
 * Messages are signed with the our {@link PrivateKey} and verified with our
 * peer's {@link PublicKey} In this way, only we should be able to sign messages
 * sent by us and anyone can verify that we sent them a message.
 * 
 * @author Joshua Spence
 */
public class AsymmetricVerification {
	/** Our public-private {@link KeyPair}. */
	protected final KeyPair ourKeys;
	
	/** The {@link PublicKey} of the peer that we are communicating with. */
	protected PublicKey peerPublicKey;
	
	/** {@link PrivateKey} used to create a signature. */
	protected PrivateKey signerKey;
	
	/** {@link PublicKey} used to verify a signature. */
	protected PublicKey verifierKey;
	
	/** The algorithm used to initialise the {@link Signature}s. */
	private final String algorithm;
	
	/** The provider used to initialise the {@link Signature}s. */
	private final String provider;
	
	/**
	 * Constructor to use a supplied public-private {@link KeyPair} for
	 * asymmetric verification.
	 * 
	 * @param algorithm The cipher algorithm to be used for signing and
	 *        verification.
	 * @param keys The public-private {@link KeyPair} to be used. The
	 *        {@link PrivateKey} will be used for signing.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	protected AsymmetricVerification(final String algorithm, final KeyPair keys) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		this.algorithm = algorithm;
		provider = null;
		ourKeys = keys;
		setSigner(ourKeys.getPrivate());
	}
	
	/**
	 * Constructor to use a supplied public-private {@link KeyPair} for
	 * asymmetric verification.
	 * 
	 * @param algorithm The {@link Cipher} algorithm to be used for signing and
	 *        verification.
	 * @param provider The {@link Cipher} provider to be used for signing and
	 *        verification.
	 * @param keys The public-private {@link KeyPair} to be used. The
	 *        {@link PrivateKey} will be used for signing.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	protected AsymmetricVerification(final String algorithm, final String provider, final KeyPair keys) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		this.algorithm = algorithm;
		this.provider = provider;
		ourKeys = keys;
		setSigner(ourKeys.getPrivate());
	}
	
	/**
	 * Get our {@link PublicKey}.
	 * 
	 * @return Our {@link PublicKey}.
	 */
	public final PublicKey getPublicKey() {
		return ourKeys.getPublic();
	}
	
	/**
	 * Get our public-private {@link KeyPair}.
	 * 
	 * @return Our public-private {@link KeyPair}.
	 */
	public final KeyPair getKeys() {
		return ourKeys;
	}
	
	/**
	 * Get the peer's {@link PublicKey}. The peer's {@link PublicKey} is used
	 * for verification.
	 * 
	 * @return The peer's {@link PublicKey}.
	 */
	public final PublicKey getPeerPublicKey() {
		return peerPublicKey;
	}
	
	/**
	 * Set the peer's {@link PublicKey}. The peer's {@link PublicKey} is used
	 * for verification.
	 * 
	 * @param peer The peer's {@link PublicKey}.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public void setPeerPublicKey(final PublicKey peer) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		peerPublicKey = peer;
		setVerifier(peerPublicKey);
	}
	
	/**
	 * Set the signer {@link PrivateKey}. This must be set before attempting to
	 * sign any data.
	 * 
	 * @param key The {@link PrivateKey} to be used for signing.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	private final void setSigner(final PrivateKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		signerKey = key;
	}
	
	/**
	 * Set the verifier {@link Key}. This must be set before attempting to
	 * verify any data.
	 * 
	 * @param key The {@link PublicKey} to be used for verification.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	private final void setVerifier(final PublicKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		verifierKey = key;
	}
	
	/**
	 * Sign data using the signer key.
	 * 
	 * @param message The message to sign.
	 * @return The signed message, encoded in base-64.
	 * 
	 * @throws SignatureException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException
	 * @throws IllegalStateException If the signer {@link Signature} hasn't been
	 *         set.
	 * @see Base64
	 */
	public byte[] sign(final String message) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
		if (signerKey == null)
			throw new IllegalStateException("Cannot perform encryption without a signer key.");
		
		return sign(message.getBytes());
	}
	
	/**
	 * Signs data using the signer key.
	 * 
	 * @param message The data to sign.
	 * @return The signed message, encoded in base-64.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws CloneNotSupportedException
	 * @throws SignatureException
	 * @throws NoSuchProviderException
	 * @throws IllegalStateException If the signer {@link Signature} hasn't been
	 *         set.
	 * @see Base64
	 */
	public byte[] sign(final byte[] message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
		if (signerKey == null)
			throw new IllegalStateException("Cannot perform encryption without a signer key.");
		
		/* Create the signer */
		Signature signer;
		if (provider == null)
			signer = Signature.getInstance(algorithm);
		else
			signer = Signature.getInstance(algorithm, provider);
		signer.initSign(signerKey);
		signer.update(message);
		
		final byte[] signedValue = signer.sign();
		final byte[] encodedValue = Base64.encodeBase64(signedValue);
		return encodedValue;
	}
	
	/**
	 * Verifies data using the verifier key.
	 * 
	 * @param message The data to be verified.
	 * @param signature The signature of the message, assumed to be encoded in
	 *        base-64.
	 * @return True if the verification passes, otherwise false.
	 * 
	 * @throws SignatureException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException
	 * @throws IllegalStateException If the decryption cipher hasn't been set.
	 * @see Base64
	 */
	public boolean verify(final String message, final byte[] signature) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
		if (verifierKey == null)
			throw new IllegalStateException("Cannot perform decryption without a verifier key.");
		
		return verify(message.getBytes(), signature);
	}
	
	/**
	 * Verifies data using the verifier key.
	 * 
	 * @param message The data to be verified.
	 * @param signature The signature of the message, assumed to be encoded in
	 *        base-64.
	 * @return True if the verification passes, otherwise false.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchProviderException
	 * @throws IllegalStateException If the decryption cipher hasn't been set.
	 * @see Base64
	 */
	public boolean verify(final byte[] message, final byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
		if (verifierKey == null)
			throw new IllegalStateException("Cannot perform decryption without a verifier key.");
		
		/* Create the verifier. */
		Signature verifier;
		if (provider == null)
			verifier = Signature.getInstance(algorithm);
		else
			verifier = Signature.getInstance(algorithm, provider);
		verifier.initVerify(verifierKey);
		verifier.update(message);
		
		return verifier.verify(Base64.decodeBase64(signature));
	}
}

/******************************************************************************
 * END OF FILE: AsymmetricVerification.java
 *****************************************************************************/
