/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet
 * FILENAME:        Utility.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     Utility functions that are common throughout StealthNet.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet;

/* Import Libraries ******************************************************** */

import java.io.File;
import java.io.IOException;
import java.net.URL;
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

import org.apache.commons.codec.binary.Base64;

import StealthNet.Security.AsymmetricEncryption;
import StealthNet.Security.EncryptedFileException;
import StealthNet.Security.RSAAsymmetricEncryption;

/* StealthNet.Utility Class Definition ************************************* */

/**
 * Utility functions that are common throughout StealthNet.
 * 
 * @author Stephen Gould
 * @author Matt Barrie
 * @author Ryan Junee
 * @author Joshua Spence
 */
public class Utility {
	/**
	 * A table of hexadecimal characters, mapping an integer to its hexadecimal
	 * character.
	 */
	public static final char[] HEXTABLE = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	
	/**
	 * The number of hexadecimal characters required to represent a single byte.
	 */
	public static final int HEX_PER_BYTE = Byte.SIZE / (int) logBase2(HEXTABLE.length);
	
	/**
	 * Function to assist with printing cryptographic keys by returning byte
	 * arrays as a {@link String} of hexadecimal numbers.
	 * 
	 * @param array The byte array to transform into a hexadecimal number.
	 * @return The {@link String} containing the hexadecimal number.
	 */
	public static String getHexValue(final byte[] array) {
		final StringBuffer buf = new StringBuffer(array.length * HEX_PER_BYTE);
		
		for (final byte element : array) {
			final int hn = (element & 0x00FF) / HEXTABLE.length;
			final int ln = element & 0x000F;
			buf.append(HEXTABLE[hn]);
			buf.append(HEXTABLE[ln]);
		}
		
		return buf.toString();
	}
	
	/**
	 * A utility function to convert a single hexadecimal character to a decimal
	 * integer.
	 * 
	 * @param hex The hexadecimal character to convert to an integer.
	 * @return The integer value of the hexadecimal character.
	 * @throws NumberFormatException
	 */
	public static int singleHexToInt(final char hex) {
		if (hex >= '0' && hex <= '9')
			return hex - '0';
		else if (hex >= 'A' && hex <= 'F')
			return hex - 'A' + 10;
		else if (hex >= 'a' && hex <= 'f')
			return hex - 'a' + 10;
		else
			throw new NumberFormatException("Character '" + hex + "' is not a valid hexadecimal character.");
	}
	
	/**
	 * Convert a hexadecimal {@link String} to the integer representing the
	 * value of the hexadecimal {@link String}.
	 * 
	 * @param hex The {@link String} to convert.
	 * @return An integer representing the hexadecimal {@link String}.
	 * @throws NumberFormatException
	 */
	public static int hexToInt(final String hex) throws NumberFormatException {
		return Integer.parseInt(hex, HEXTABLE.length);
	}
	
	/**
	 * Convert an integer to a hexadecimal {@link String} representing the same
	 * value. The length of the hexadecimal {@link String} will be equal to the
	 * length that would be required to encode Integer.MAX_VALUE as a
	 * hexadecimal {@link String}.
	 * 
	 * @param value The integer to convert.
	 * @return The hexadecimal {@link String} representing the integer.
	 */
	public static String intToHex(final int value) {
		String result = Integer.toHexString(value);
		
		/*
		 * Pad the result to use the full (Integer.SIZE / Byte.SIZE) bytes of an
		 * integer.
		 */
		while (result.length() < HEX_PER_BYTE * (Integer.SIZE / Byte.SIZE))
			result = "0" + result;
		
		return result;
	}
	
	/**
	 * Find the logarithm of a number in base 2.
	 * 
	 * @param x The number to find the logarithm of.
	 * @return The base-2 logarithm.
	 */
	public static double logBase2(final double x) {
		return Math.log(x) / Math.log(2);
	}
	
	/**
	 * Retrieve public keys. The keys will first try to be retrieved from the
	 * JAR and then from the file system. Otherwise no key will be returned.
	 * 
	 * @param publicKeyPath The path to the public key file.
	 * @return The requested public key, or null if it cannot be found.
	 * 
	 * @see RSAAsymmetricEncryption
	 */
	public static PublicKey getPublicKey(final String publicKeyPath) {
		final URL publicKeyJAR = Utility.class.getClassLoader().getResource(publicKeyPath);
		final boolean publicKeyFileExists = new File(publicKeyPath).exists();
		
		/*
		 * Try to read keys from the JAR file first. If that doesn't work, then
		 * try to read keys from the file system. If that doesn't work, return
		 * null.
		 */
		try {
			if (publicKeyJAR != null)
				/* Read public key from JAR. */
				return RSAAsymmetricEncryption.readPublicKeyFromFile(publicKeyJAR);
			else if (publicKeyFileExists)
				/* Read public keys from file system. */
				return RSAAsymmetricEncryption.readPublicKeyFromFile(publicKeyPath);
			else
				return null;
		} catch (final Exception e) {
			System.err.println(e.getMessage());
			return null;
		}
	}
	
	/**
	 * Retrieve public-private keys. The keys will first try to be retrieved
	 * from the JAR and then from the file system. Finally, new public-private
	 * keys will be created.
	 * 
	 * @param publicKeyPath The path to the public key file.
	 * @param privateKeyPath The path to the private key file.
	 * @param privateKeyPassword The password to decrypt the private key file.
	 * @return An {@link AsymmetricEncryption} provider for the keys.
	 * 
	 * @throws EncryptedFileException
	 * @throws IOException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeySpecException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAttributeValueException
	 * @throws InvalidKeyException
	 * 
	 * @see RSAAsymmetricEncryption
	 */
	public static KeyPair getPublicPrivateKeys(final String publicKeyPath, final String privateKeyPath, final String privateKeyPassword) throws InvalidKeyException, InvalidAttributeValueException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, IOException, EncryptedFileException {
		final URL publicKeyJAR = Utility.class.getClassLoader().getResource(publicKeyPath);
		final URL privateKeyJAR = Utility.class.getClassLoader().getResource(privateKeyPath);
		final File publicKeyFile = new File(publicKeyPath);
		final File privateKeyFile = new File(privateKeyPath);
		final boolean publicKeyFileExists = publicKeyFile.exists();
		final boolean privateKeyFileExists = privateKeyFile.exists();
		
		/*
		 * Try to read keys from the JAR file first. If that doesn't work, then
		 * try to read keys from the file system. If that doesn't work, then
		 * create new keys.
		 */
		if (publicKeyJAR != null && privateKeyJAR != null) {
			/* Read public/private keys from JAR. */
			PublicKey publicKey = null;
			PrivateKey privateKey = null;
			
			try {
				publicKey = RSAAsymmetricEncryption.readPublicKeyFromFile(publicKeyJAR);
			} catch (final Exception e) {
				System.err.println("Unable to read public key from file.");
				e.printStackTrace();
				return null;
			}
			
			try {
				privateKey = RSAAsymmetricEncryption.readPrivateKeyFromFile(privateKeyJAR, privateKeyPassword);
			} catch (final Exception e) {
				System.err.println("Unable to read private key from file.");
				e.printStackTrace();
				return null;
			}
			
			return new KeyPair(publicKey, privateKey);
		} else if (publicKeyFileExists && privateKeyFileExists) {
			/* Read public/private keys from file system. */
			PublicKey publicKey = null;
			PrivateKey privateKey = null;
			
			try {
				publicKey = RSAAsymmetricEncryption.readPublicKeyFromFile(publicKeyPath);
			} catch (final Exception e) {
				System.err.println("Unable to read public key from file.");
				e.printStackTrace();
				return null;
			}
			
			try {
				privateKey = RSAAsymmetricEncryption.readPrivateKeyFromFile(privateKeyPath, privateKeyPassword);
			} catch (final EncryptedFileException e) {
				throw e;
			} catch (final Exception e) {
				System.err.println("Unable to read private key from file.");
				e.printStackTrace();
				return null;
			}
			
			return new KeyPair(publicKey, privateKey);
		} else {
			/*
			 * Create new public-private keys.
			 */
			
			/* Create the parent directories if they don't already exist. */
			new File(publicKeyFile.getParent()).mkdirs();
			new File(privateKeyFile.getParent()).mkdirs();
			
			/* Create new public/private keys. */
			KeyPair kp = null;
			try {
				kp = RSAAsymmetricEncryption.generateKeys();
			} catch (final Exception e) {
				System.err.println("Unable to generate public-private keys.");
				e.printStackTrace();
				return null;
			}
			
			/* Save the keys to the file system. */
			try {
				RSAAsymmetricEncryption.savePublicKeyToFile(kp.getPublic(), publicKeyPath);
			} catch (final Exception e) {
				System.err.println("Unable to save private key to file.");
				e.printStackTrace();
				return null;
			}
			
			try {
				RSAAsymmetricEncryption.savePrivateKeyToFile(kp.getPrivate(), privateKeyPath, privateKeyPassword);
			} catch (final Exception e) {
				System.err.println("Unable to save private key to file.");
				e.printStackTrace();
				return null;
			}
			
			return kp;
		}
	}
	
	/**
	 * Get the user name that a {@link Server} should use to log in to the
	 * {@link Bank}.
	 * 
	 * @param publicKey The {@link Server}'s {@link PublicKey}.
	 * @return The user name that a {@link Server} should use to log in to the
	 *         {@link Bank}.
	 */
	public static String getServerUserName(final PublicKey publicKey) {
		return "server#" + Base64.encodeBase64String(publicKey.getEncoded());
	}
}

/******************************************************************************
 * END OF FILE: Utility.java
 *****************************************************************************/
