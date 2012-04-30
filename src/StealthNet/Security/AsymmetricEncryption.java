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
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/* StealthNet.Security.AsymmetricEncryption Interface Definition *************/

/**
 * An interface to provide public-private key (asymmetric) encryption. Messages 
 * are encrypted with the peer's public key and decrypted with our private key.
 * 
 * Asymmetric encryption is slow and should only be used until it is possible to
 * securely use symmetric encryption.
 *
 * @author Joshua Spence
 */
public interface AsymmetricEncryption extends Encryption {
	/**
	 * Save the public key to a file so that it can be retrieved at a later 
	 * time. The public key will not be password protected in any way.
	 * 
	 * @param filename The path of the file to which the public key should be 
	 * saved.
	 * 
	 * @throws IOException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws InvalidKeySpecException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchProviderException 
	 */
	public void savePublicKeyToFile(String filename) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException;
	
	/**
	 * Save the private key to a file so that it can be retrieved at a later 
	 * time. The private key file will be password protected.
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
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchProviderException 
	 */
	public void savePrivateKeyToFile(String filename, String password) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException;
	
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
	 * @throws NoSuchProviderException 
	 */
	public void setPeerPublicKey(PublicKey peer) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException;
	
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