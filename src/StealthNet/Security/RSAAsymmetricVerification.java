/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        RSAAsymmetricVerification.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     A class to provide RSA asymmetric verification.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet.Security;

/* Import Libraries ******************************************************** */

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.crypto.NoSuchPaddingException;

/* StealthNet.Security.RSAAsymmetricVerification Interface Definition ****** */

/**
 * A class to provide RSA asymmetric verification. Signing will be performed
 * using our {@link PrivateKey}. Verification will be performed using our peer's
 * {@link PublicKey}.
 * 
 * @author Joshua Spence
 * @see AsymmetricVerification
 */
public class RSAAsymmetricVerification extends AsymmetricVerification {
	/**
	 * The algorithm to be used for the signer and verifier {@link Signature}.
	 */
	public static final String ALGORITHM = "SHAwithRSA";
	
	/**
	 * Constructor to use the supplied public-private {@link KeyPair} for
	 * signing. Verifying will not yet be enabled.
	 * 
	 * @param ourKeys Our public-private {@link KeyPair}.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public RSAAsymmetricVerification(final KeyPair ourKeys) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		super(ALGORITHM, ourKeys);
	}
	
	/**
	 * Constructor to use the supplied public-private {@link KeyPair} for
	 * signing and the supplied peer {@link PublicKey} for verifier.
	 * 
	 * @param ourKeys Our public-private {@link KeyPair}.
	 * @param peer The {@link PublicKey} of the the peer of the communications,
	 *        used for verifing. If null, then verifying will be unavailable.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public RSAAsymmetricVerification(final KeyPair ourKeys, final PublicKey peer) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		super(ALGORITHM, ourKeys);
		super.setPeerPublicKey(peer);
	}
}

/******************************************************************************
 * END OF FILE: RSAAsymmetricVerification.java
 *****************************************************************************/
