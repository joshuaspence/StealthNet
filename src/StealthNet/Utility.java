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

package StealthNet;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.management.InvalidAttributeValueException;

import StealthNet.Security.AsymmetricEncryption;
import StealthNet.Security.EncryptedFileException;
import StealthNet.Security.RSAAsymmetricEncryption;

/* Import Libraries **********************************************************/

/* StealthNet.Utility Class Definition ***************************************/

/**
 * Utility functions that are common throughout StealthNet.
 *  
 * @author Stephen Gould
 * @author Matt Barrie
 * @author Ryan Junee
 * @author Joshua Spence
 */
public class Utility {
	/** Hexadecimal characters. */
    public static final char[] HEXTABLE = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    
    /** Number of hexadecimal characters required to represent a single byte. */
    public static final int HEX_PER_BYTE = Byte.SIZE / (int) logBase2(HEXTABLE.length);
    
	/**
     * Function to assist with printing cryptographic keys by returning byte 
     * arrays as a hexadecimal number.
     * 
     * @param array The byte array to transformx into a hexadecimal number.
     * @return The string containing the hexadecimal number.
     */    
    public static String getHexValue(byte[] array) {
		final StringBuffer buf = new StringBuffer(array.length * HEX_PER_BYTE);
		
		for (int cx = 0; cx < array.length; cx++) {
			final int hn = ((int) (array[cx]) & 0x00FF) / HEXTABLE.length;
			final int ln = ((int) (array[cx]) & 0x000F);
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
     */
    public static int singleHexToInt(char hex) {
             if ((hex >= '0') && (hex <= '9')) return (hex - '0');
        else if ((hex >= 'A') && (hex <= 'F')) return (hex - 'A' + 10);
        else if ((hex >= 'a') && (hex <= 'f')) return (hex - 'a' + 10);
        else return 0;
    }
    
	/**
     * Convert a hexadecimal string to an integer.
     * 
     * @param hex The string to convert.
     * @return An integer representing the hexadecimal string.
     * @throws NumberFormatException
     */
	public static int hexToInt(String hex) throws NumberFormatException {
    	return Integer.parseInt(hex, HEXTABLE.length);
	}
	
	/**
     * Convert an integer to a hexadecimal string. The length of the hexadecimal 
     * string will be equal to the length that would be required to encode
     * Integer.MAX_VALUE as a hexadecimal string.
     * 
     * @param value The integer to convert.
     * @return The hexadecimal string representing the integer.
     */
	public static String intToHex(int value) {
		String result = Integer.toHexString(value);
		
		/** Pad the result to use the full 4 bytes of an integer. */
		while (result.length() < (HEX_PER_BYTE * (Integer.SIZE / Byte.SIZE)))
			result = "0" + result;
		
		return result;
	}
	
	/**
	 * Find the logarithm of a number in base 2.
	 * 
	 * @param x The number to find the logarithm of.
	 * @return The base-2 logarithm.
	 */
	public static double logBase2(double x) {
		return (Math.log(x) / Math.log(2));
	}
	
	/**
	 * Retrieve public keys. The keys will first try to be retrieved from the 
	 * JAR and then from the file system. Otherwise no key will be returned.
	 * 
	 * @param publicKeyPath The path to the public key file.
	 * @return The requested public key, or null if it cannot be found.
	 */
	public static PublicKey getPublicKey(String publicKeyPath) {
		final URL publicKeyJAR = Utility.class.getClassLoader().getResource(publicKeyPath);
    	final boolean publicKeyFileExists = new File(publicKeyPath).exists();
    	
    	/** 
    	 * Try to read keys from the JAR file first. If that doesn't work, then
    	 * try to read keys from the file system. If that doesn't work, return 
    	 * null.
    	 */
    	try {
    		if (publicKeyJAR != null) {
    			/** Read public key from JAR. */
	    		return RSAAsymmetricEncryption.readPublicKeyFromFile(publicKeyJAR);
    		} else if (publicKeyFileExists) {
    			/** Read public keys from file system. */
	    		return RSAAsymmetricEncryption.readPublicKeyFromFile(publicKeyPath);
    		} else {
    			return null;
    		}
		} catch (Exception e) {
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
	 * @return An AsymmetricEncryption provider for the keys.
	 * 
	 * @throws IOException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws EncryptedFileException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchProviderException 
	 * @throws InvalidAttributeValueException 
	 */
	public static AsymmetricEncryption getPublicPrivateKeys(String publicKeyPath, String privateKeyPath, String privateKeyPassword) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IOException, InvalidAlgorithmParameterException, EncryptedFileException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidAttributeValueException {
		final URL publicKeyJAR = Utility.class.getClassLoader().getResource(publicKeyPath);
    	final URL privateKeyJAR = Utility.class.getClassLoader().getResource(privateKeyPath);
    	final File publicKeyFile = new File(publicKeyPath);
    	final File privateKeyFile = new File(privateKeyPath);
    	final boolean publicKeyFileExists = publicKeyFile.exists();
    	final boolean privateKeyFileExists = privateKeyFile.exists();
    	
    	/** 
    	 * Try to read keys from the JAR file first. If that doesn't work, then
    	 * try to read keys from the file system. If that doesn't work, then 
    	 * create new keys.
    	 */
		if (publicKeyJAR != null && privateKeyJAR != null) {
			/** Read public/private keys from JAR. */
    		return new RSAAsymmetricEncryption(publicKeyJAR, privateKeyJAR, privateKeyPassword, null);
		}
		
		if (publicKeyFileExists && privateKeyFileExists) {
			/** Read public/private keys from file system. */
    		return new RSAAsymmetricEncryption(publicKeyPath, privateKeyPath, privateKeyPassword, null);
		}
		
		/** Create new public-private keys. */
		
		/** Create the parent directories if they don't already exist. */
    	new File(publicKeyFile.getParent()).mkdirs();
    	new File(privateKeyFile.getParent()).mkdirs();
    	
		/** Create new public/private keys. */
		final AsymmetricEncryption aep = new RSAAsymmetricEncryption(null);
		aep.savePublicKeyToFile(publicKeyPath);
		aep.savePrivateKeyToFile(privateKeyPath, privateKeyPassword);
		return aep;
	}
}

/******************************************************************************
 * END OF FILE: Utility.java
 *****************************************************************************/