/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        AsymmetricEncryption.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     An interface for key exchange protocols to implement 
 * 					asymmetric (public-private key) encryption.
 *
 *****************************************************************************/

package StealthNet.Security;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/* Import Libraries **********************************************************/

/* StealthNet.Security.AsymmetricEncryption Interface Definition *************/

/**
 * An interface to provide public-private key (asymmetric) encryption.
 *
 * @author Joshua Spence
 */
public interface AsymmetricEncryption extends Encryption {
	/**
	 * Save the public key to a file so that it can be retrieved at a later 
	 * time.
	 * 
	 * @param filename The path of the file to which the public key should be 
	 * saved.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	public void savePublicKeyToFile(String filename) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException;
	
	/**
	 * Save the private key to a file so that it can be retrieved at a later 
	 * time.
	 * 
	 * @param filename The path of the file to which the public key should be 
	 * saved.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	public void savePrivateKeyToFile(String filename) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException;
	
	/**
	 * Get our public key.
	 * 
	 * @return Our public key.
	 */
	public PublicKey getPublicKey();
	
	/**
	 * Get the peer's public key.
	 * 
	 * @return The peer's public key.
	 */
	public PublicKey getPeerPublicKey();
	
	/**
	 * Get our private key.
	 * 
	 * @return Our private key.
	 */
	public PrivateKey getPrivateKey();
}

/******************************************************************************
 * END OF FILE:     AsymmetricEncryption.java
 *****************************************************************************/