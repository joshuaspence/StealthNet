/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        AsymmetricEncryption.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     A base class for key exchange protocols to implement 
 * 					asymmetric (public-private key) encryption.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet.Security;

/* Import Libraries ******************************************************** */

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.management.InvalidAttributeValueException;

import StealthNet.EncryptedFile;

/* StealthNet.Security.AsymmetricEncryption Class Definition ************** */

/**
 * A base class to provide public-private key (asymmetric) encryption. Messages
 * are encrypted with the peer's {@link PublicKey} and decrypted with our
 * {@link PrivateKey} In this way, only we should be able to decrypt messages
 * sent to us and only the peer should be able to decrypt messages sent from us.
 * <p> Asymmetric encryption is slow and should only be used until it is
 * possible to securely use symmetric encryption.
 * 
 * @author Joshua Spence
 * @see Encryption
 */
public class AsymmetricEncryption extends Encryption {
	/** Our public-private {@link KeyPair}. */
	protected final KeyPair ourKeys;
	
	/** The {@link PublicKey} of the peer that we are communicating with. */
	protected PublicKey peerPublicKey;
	
	/**
	 * Constructor to use a supplied public-private {@link KeyPair} for
	 * asymmetric encryption.
	 * 
	 * @param algorithm The cipher algorithm to be used for encryption and
	 *        decryption.
	 * @param keys The public-private {@link KeyPair} to be used. The
	 *        {@link PrivateKey} will be used for decryption.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	protected AsymmetricEncryption(final String algorithm, final KeyPair keys) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		super(algorithm);
		ourKeys = keys;
		super.setDecryption(ourKeys.getPrivate());
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
	 * for encryption.
	 * 
	 * @return The peer's {@link PublicKey}.
	 */
	public final PublicKey getPeerPublicKey() {
		return peerPublicKey;
	}
	
	/**
	 * Set the peer's {@link PublicKey}. The peer's {@link PublicKey} is used
	 * for encryption.
	 * 
	 * @param peer The peer's {@link PublicKey}.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public void setPeerPublicKey(final PublicKey peer) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		peerPublicKey = peer;
		super.setEncryption(peerPublicKey);
	}
	
	/**
	 * A utility function to write the modulus and exponent of a key to a file
	 * encrypted with a password.
	 * 
	 * @param filename The path of the file to write to.
	 * @param mod The modulus of the key.
	 * @param exp The exponent of the key.
	 * @param password A password to encrypt the file. Null for no password.
	 * 
	 * @throws IOException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeySpecException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAttributeValueException
	 * @throws InvalidKeyException
	 */
	protected static void writeKeyToFile(final String filename, final BigInteger mod, final BigInteger exp, final String password) throws IOException, InvalidKeyException, InvalidAttributeValueException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException {
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		final BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(outputStream);
		final DataOutputStream dataOutputStream = new DataOutputStream(bufferedOutputStream);
		
		/* Write the modulus and exponent to a byte array. */
		try {
			/* Write the modulus to the output byte array. */
			final byte[] modArray = mod.toByteArray();
			dataOutputStream.writeInt(modArray.length);
			dataOutputStream.write(modArray);
			
			/* Write the exponent to a byte array. */
			final byte[] expArray = exp.toByteArray();
			dataOutputStream.writeInt(expArray.length);
			dataOutputStream.write(expArray);
		} catch (final Exception e) {
			throw new IOException("Unexpected error", e);
		} finally {
			dataOutputStream.flush();
			bufferedOutputStream.flush();
			outputStream.flush();
			dataOutputStream.close();
			bufferedOutputStream.close();
		}
		
		/* Write the byte array to an (un)encrypted file. */
		if (password != null) {
			final EncryptedFile file = new EncryptedFile(outputStream.toByteArray(), password);
			file.writeToFile(new File(filename));
		} else {
			final FileOutputStream fileOutputStream = new FileOutputStream(filename);
			
			try {
				fileOutputStream.write(outputStream.toByteArray());
			} catch (final Exception e) {
				throw new IOException("Unexpected error", e);
			} finally {
				fileOutputStream.flush();
				fileOutputStream.close();
			}
		}
		
		/* Close the output stream. */
		outputStream.close();
	}
}

/******************************************************************************
 * END OF FILE: AsymmetricEncryption.java
 *****************************************************************************/
