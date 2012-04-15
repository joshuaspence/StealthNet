/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie and Stephen Gould
 *
 * PROJECT:         StealthNet
 * FILENAME:        StealthNetEncryption.java
 * AUTHORS:         Joshua Spence and Ahmad Al Mutawa
 * DESCRIPTION:     Implementation of AES encryption for ELEC5616 programming 
 * assignment.
 * VERSION:         1.0
 *
 *****************************************************************************/

package StealthNet;

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

/* StealthNetEncryption Class Definition *************************************/

/**
 * A class used to encrypt and decrypt messages, in order to provide 
 * confidentiality.
 * 
 * Ideally, only the sender should be able to encrypt the message; and only the
 * receiver should be able to decrypt the message.
 * 
 * @author Joshua Spence
 */
public class StealthNetEncryption {
	/** Encryption key and cipher. */
	private final SecretKey encryptionKey;
	private final Cipher encryptionCipher;
	
	/** Decryption key and cipher. */
	private final SecretKey decryptionKey;
	private final Cipher decryptionCipher;
	
	private IvParameterSpec ips;
	
	/** String constants. */
	// {
	public static final String HASH_ALGORITHM = "MD5";
	public static final String KEY_ALGORITHM = "AES";
	public static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
	// }
	
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
	public StealthNetEncryption(SecretKey encryptKey, SecretKey decryptKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		this.encryptionKey = encryptKey;
        this.decryptionKey = decryptKey;
        
        /** 
         * Generate the initialisation vector using a seeded random number
         * generator.
         */
        byte[] initializationVector = new byte[16];
        final Random ivGenerator = new Random(encryptKey.hashCode());
        for (int i = 0; i < 16; i++)
        	initializationVector[i] = (byte) ivGenerator.nextInt();
        
        this.ips = new IvParameterSpec(initializationVector);
        
        /** Initialise encryption cipher. */
        encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
		encryptionCipher.init(Cipher.ENCRYPT_MODE, encryptionKey, ips);
		
		/** Initialise decryption cipher. */
		decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
		decryptionCipher.init(Cipher.DECRYPT_MODE, decryptionKey, ips);
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
	 * Decrypts a message.
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
	 * Decrypts a message.
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
