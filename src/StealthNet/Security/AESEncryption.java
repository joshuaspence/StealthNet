/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        AESEncryption.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     Implementation of AES encryption for encrypting and 
 * 					decrypting StealthNet communications.
 * VERSION:         1.0
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
	/** Encryption key and cipher. */
	private final SecretKey encryptionKey;
	private final Cipher encryptionCipher;
	
	/** Decryption key and cipher. */
	private final SecretKey decryptionKey;
	private final Cipher decryptionCipher;
	
	private final IvParameterSpec encryptionIPS;
	private final IvParameterSpec decryptionIPS;
	
	/** String constants. */
	public static final String HASH_ALGORITHM = "MD5";
	public static final String KEY_ALGORITHM = "AES";
	public static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
	
	/**
	 * Constructor.
	 * 
	 * @param key The SecretKey to be used for encryption and decryption.
	 * 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	public AESEncryption(SecretKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		this.encryptionKey = key;
        this.decryptionKey = key;
        
        /** 
         * Generate the initialisation vector using a seeded random number
         * generator, with the seed equal to the has of the encryption key. In 
         * this way, both peers should generate the same initialisation 
         * vectors.
         */
        final byte[] IV = new byte[16];
        final Random IVGenerator = new Random(key.hashCode());
        for (int i = 0; i < 16; i++)
        	IV[i] = (byte) IVGenerator.nextInt();
        this.encryptionIPS = new IvParameterSpec(IV);
        this.decryptionIPS = new IvParameterSpec(IV);
        
        
        /** Initialise encryption cipher. */
        encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
		encryptionCipher.init(Cipher.ENCRYPT_MODE, encryptionKey, this.encryptionIPS);
		//System.out.println("Encryption block size = " + encryptionCipher.getBlockSize() + " bytes");
		//System.out.println("Encryption key length = " + (encryptionIPS.getIV().length * 8) + " bits");
		
		/** Initialise decryption cipher. */
		decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
		decryptionCipher.init(Cipher.DECRYPT_MODE, decryptionKey, this.decryptionIPS);
		//System.out.println("Decryption block size = " + encryptionCipher.getBlockSize() + " bytes");
		//System.out.println("Decryption key length = " + (encryptionIPS.getIV().length * 8) + " bits");
	}
	
	/**
	 * Constructor.
	 * 
	 * @param encryptKey The SecretKey to be used for encryption.
	 * @param decryptKey The SecretKey to be used for decryption.
	 * 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	public AESEncryption(SecretKey encryptKey, SecretKey decryptKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		this.encryptionKey = encryptKey;
        this.decryptionKey = decryptKey;
        
        /** 
         * Generate the initialisation vector using a seeded random number
         * generator, with the seed equal to the has of the encryption key. In 
         * this way, both peers should generate the same initialisation 
         * vectors.
         */
        final byte[] encryptionIV = new byte[16];
        final Random encryptionIVGenerator = new Random(encryptKey.hashCode());
        for (int i = 0; i < 16; i++)
        	encryptionIV[i] = (byte) encryptionIVGenerator.nextInt();
        this.encryptionIPS = new IvParameterSpec(encryptionIV);
        
        final byte[] decryptionIV = new byte[16];
        final Random decryptionIVGenerator = new Random(decryptKey.hashCode());
        for (int i = 0; i < 16; i++)
        	decryptionIV[i] = (byte) decryptionIVGenerator.nextInt();
        this.decryptionIPS = new IvParameterSpec(encryptionIV);
        
        /** Initialise encryption cipher. */
        encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
		encryptionCipher.init(Cipher.ENCRYPT_MODE, encryptionKey, this.encryptionIPS);
		
		/** Initialise decryption cipher. */
		decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
		decryptionCipher.init(Cipher.DECRYPT_MODE, decryptionKey, this.decryptionIPS);
	}
	
	/**
	 * Encrypts a message using the encryption key.
	 * 
	 * @param cleartext The message to encrypt.
	 * @return The encrypted message.
	 * 
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException 
	 */
	public String encrypt(String cleartext) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		return encrypt(cleartext.getBytes());
	}
	
	/**
	 * Encrypts a message using the encryption key.
	 * 
	 * @param cleartext The message to encrypt.
	 * @return The encrypted message.
	 * 
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException 
	 */
	public String encrypt(byte[] cleartext) throws IllegalBlockSizeException, BadPaddingException {		
		byte[] encryptedValue = encryptionCipher.doFinal(cleartext);
        byte[] encodedValue = Base64.encodeBase64(encryptedValue);    
        return new String(encodedValue);
	}
	
	/**
	 * Decrypts a message using the decryption key.
	 * 
	 * @param ciphertext The message to be decrypted.
	 * @return The cleartext message.
	 * 
	 * @throws UnsupportedEncodingException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public String decrypt(String ciphertext) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {	 
		return decrypt(ciphertext.getBytes());
	}
	
	/**
	 * Decrypts a message using the decryption key.
	 * 
	 * @param ciphertext The message to be decrypted.
	 * @return The cleartext message.
	 * 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public String decrypt(byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException {
		byte[] decodedValue = Base64.decodeBase64(ciphertext);
		byte[] decryptedValue = decryptionCipher.doFinal(decodedValue);
		return new String(decryptedValue);
	}
}

/******************************************************************************
 * END OF FILE:     AESEncryption.java
 *****************************************************************************/