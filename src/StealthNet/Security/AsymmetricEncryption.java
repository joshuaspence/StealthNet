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

/* Import Libraries **********************************************************/

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.NoSuchPaddingException;

/* StealthNet.Security.AsymmetricEncryption Interface Definition *************/

/**
 * An interface to provide public-private key (asymmetric) encryption. Messages 
 * are encrypted with the peer's public key and decrypted with our private key.
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
	 * @throws IOException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws InvalidKeySpecException 
	 */
	public void savePublicKeyToFile(String filename) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, NoSuchPaddingException;
	
	/**
	 * Save the private key to a file so that it can be retrieved at a later 
	 * time.
	 * 
	 * @param filename The path of the file to which the public key should be 
	 * saved.
	 * @param password The password to encrypt the file.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	public void savePrivateKeyToFile(String filename, String password) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException;
	
	/**
	 * Get our public key.
	 * 
	 * @return Our public key.
	 */
	public PublicKey getPublicKey();
	
	/**
	 * Get the peer's public key. The peer's public key is used for encryption.
	 * 
	 * @return The peer's public key.
	 */
	public PublicKey getPeerPublicKey();
	
	/**
	 * Set the peer's public key. The peer's public key is used for encryption.
	 * 
	 * @param peer The peer's public key.
	 * 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public void setPeerPublicKey(PublicKey peer) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException;
	
	/**
	 * Get our private key. Our private key is used for decryption.
	 * 
	 * @return Our private key.
	 */
	public PrivateKey getPrivateKey();
}

/******************************************************************************
 * END OF FILE:     AsymmetricEncryption.java
 *****************************************************************************/