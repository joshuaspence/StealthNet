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
import java.security.spec.InvalidKeySpecException;

/* Import Libraries **********************************************************/

/* StealthNet.Security.AsymmetricEncryption Interface Definition *************/

/**
 * TODO
 *
 * @author Joshua Spence
 */
public interface AsymmetricEncryption extends Encryption {
	/**
	 * TODO
	 * 
	 * @param filename
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	public void savePublicKeyToFile(String filename) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException;
	
	/**
	 * TODO
	 * 
	 * @param filename
	 */
	public void savePrivateKeyToFile(String filename) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException;
	
	/**
	 * TODO
	 * 
	 * @param filename
	 */
	public void restorePublicKeyFromFile(String filename);
	
	/**
	 * TODO
	 * 
	 * @param filename
	 */
	public void restorePrivateKeyFromFile(String filename);
}

/******************************************************************************
 * END OF FILE:     AsymmetricEncryption.java
 *****************************************************************************/