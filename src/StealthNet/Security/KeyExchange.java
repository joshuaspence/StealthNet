/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        KeyExchange.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     An interface for key exchange protocols to implement 
 * 					authentication in StealthNet.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet.Security;

/* Import Libraries ******************************************************** */

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;

/* StealthNet.Security.KeyExchange Interface Definition ******************** */

/**
 * This is an interface to provide authentication methods to StealthNet through
 * use of a key exchange protocol. This involves both peer generate some private
 * key and some public key, exchanging public keys, and then being able to
 * generate a shared secret key using the received public key.
 * 
 * @author Joshua Spence
 */
public interface KeyExchange {
	/**
	 * Gets the public key of this end of the key exchange.
	 * 
	 * @return The public key of this end of the key exchange.
	 */
	public BigInteger getPublicKey();
	
	/**
	 * Get the shared {@link SecretKey} that has been agreed on through the key
	 * exchange protocol.
	 * 
	 * @param peerPublicValue The peer's public key.
	 * @return The shared {@link SecretKey}. Both peers should generate the same
	 *         {@link SecretKey}.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 */
	public SecretKey getSharedSecret(BigInteger peerPublicValue) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException;
}

/******************************************************************************
 * END OF FILE: KeyExchange.java
 *****************************************************************************/
