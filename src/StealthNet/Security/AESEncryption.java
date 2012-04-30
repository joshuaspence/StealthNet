/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        AESEncryption.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     Implementation of AES encryption for encrypting and 
 * 					decrypting StealthNet communications.
 *
 *****************************************************************************/

package StealthNet.Security;

/* Import Libraries **********************************************************/

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;

/* StealthNet.Security.AESEncryption Class Definition ************************/

/**
 * A class used to encrypt and decrypt messages using AES.
 * 
 * @author Joshua Spence
 */
public class AESEncryption implements Encryption {
	/** Keys and ciphers. */
	private final SecretKey key;
	private final IvParameterSpec ips;
	private final Cipher encryptionCipher;
	private final Cipher decryptionCipher;
	
	/** Constants. */
	public static final String HASH_ALGORITHM = "MD5";
	public static final String KEY_ALGORITHM = "AES";
	public static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
	private static final int SALT_BYTES = 16;
	
	/**
	 * Constructor.
	 * 
	 * @param key The SecretKey to be used for both encryption and decryption.
	 * 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeyException 
	 */
	public AESEncryption(SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		this.key = key;
        
        /** 
         * Generate the initialisation vector using a seeded random number
         * generator, with the seed equal to the hash of the encryption key. In 
         * this way, both peers should generate the same initialisation 
         * vectors.
         * 
         * NOTE: IVGenerator must be of class `Random' and not `SecureRandom'. 
         * Otherwise the peers will generate different initialisation vectors, 
         * despite having the same seed to the random number generator.
         */
        final byte[] iv = new byte[SALT_BYTES];
        final long salt = key.hashCode();
        final Random IVGenerator = new Random(salt);
        
        for (int i = 0; i < 16; i++)
        	iv[i] = (byte) IVGenerator.nextInt();
        this.ips = new IvParameterSpec(iv);
        
        /** Initialise encryption cipher. */
        this.encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
        this.encryptionCipher.init(Cipher.ENCRYPT_MODE, this.key, this.ips);
		//System.out.println("Encryption block size = " + this.encryptionCipher.getBlockSize() + " bytes");
		//System.out.println("Encryption key length = " + (this.ips.getIV().length * 8) + " bits");
		
		/** Initialise decryption cipher. */
		this.decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
		this.decryptionCipher.init(Cipher.DECRYPT_MODE, this.key, this.ips);
		//System.out.println("Decryption block size = " + this.encryptionCipher.getBlockSize() + " bytes");
		//System.out.println("Decryption key length = " + (this.ips.getIV().length * 8) + " bits");
	}
	
	/**
	 * Encrypts a message using the encryption key. Performs the opposite of the
	 * decrypt(String) function.
	 * 
	 * @param cleartext The message to encrypt.
	 * @return The encrypted message, encoded in base 64.
	 * 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * 
	 */
	public byte[] encrypt(String cleartext) throws IllegalBlockSizeException, BadPaddingException {
		return encrypt(cleartext.getBytes());
	}
	
	/**
	 * Encrypts a message using the encryption key. Performs the opposite of the
	 * decrypt(byte[]) function.
	 * 
	 * @param cleartext The message to encrypt.
	 * @return The encrypted message, encoded in base 64.
	 * 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public byte[] encrypt(byte[] cleartext) throws IllegalBlockSizeException, BadPaddingException {		
		final byte[] encryptedValue = encryptionCipher.doFinal(cleartext);
		final byte[] encodedValue = Base64.encodeBase64(encryptedValue);    
        return encodedValue;
	}
	
	/**
	 * Decrypts a message using the decryption key. Performs the opposite of the
	 * encrypt(String) function.
	 * 
	 * @param ciphertext The message to be decrypted, assumed to be encoded in
	 * base 64.
	 * @return The cleartext message.
	 * 
	 * @throws UnsupportedEncodingException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public byte[] decrypt(String ciphertext) throws IllegalBlockSizeException, BadPaddingException {	 
		return decrypt(ciphertext.getBytes());
	}
	
	/**
	 * Decrypts a message using the decryption key. Performs the opposite of the
	 * encrypt(byte[]) function.
	 * 
	 * @param ciphertext The message to be decrypted, assumed to be encoded in
	 * base 64.
	 * @return The cleartext message.
	 * 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public byte[] decrypt(byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException {
		final byte[] decodedValue = Base64.decodeBase64(ciphertext);
		final byte[] decryptedValue = decryptionCipher.doFinal(decodedValue);
		return decryptedValue;
	}
}

/******************************************************************************
 * END OF FILE:     AESEncryption.java
 *****************************************************************************/