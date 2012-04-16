/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie and Stephen Gould
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        KeyExchange.java
 * AUTHORS:         Joshua Spence and Ahmad Al Mutawa
 * DESCRIPTION:     An interface for key exchange protocols to implement 
 * 					authentication in StealthNet.
 * VERSION:         1.0
 *
 *****************************************************************************/

package StealthNet.Security;

/* Import Libraries **********************************************************/

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;

/* StealthNet.Security.KeyExchange Interface Definition **********************/

/**
 * This is an interface to provide authentication methods to StealthNet through
 * use of a key exchange protocol.
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
	 * Get the secret data that has been agreed on through the key exchange
	 * protocol.
	 *
	 * @param peerPublicValue The peer's public key.
	 * @return The secret key.
	 * 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws IllegalStateException 
	 * @throws InvalidKeyException 
	 */
	 public SecretKey getSharedSecret(BigInteger peerPublicValue) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalStateException;
}

/******************************************************************************
 * END OF FILE:     KeyExchange.java
 *****************************************************************************/