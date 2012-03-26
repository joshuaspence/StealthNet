package StealthNet;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * A class used to encrypt and decrypt messages.
 * 
 * @author Joshua Spence
 */
public class StealthNetEncryption {
	private final SecretKey encryption_key;
	private final Cipher encryption_cipher;
	
	private SecretKey decryption_key;
	private Cipher decryption_cipher;
	
	private static final String ENCRYPTION_ALGORITHM = "AES";
	private static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
	
	public StealthNetEncryption() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        KeyGenerator keygen = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
        
        encryption_key = keygen.generateKey();
        encryption_cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        encryption_cipher.init(Cipher.ENCRYPT_MODE, encryption_key);
	}
	
	public void setDecryptionKey(SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		decryption_key = key;
		decryption_cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		decryption_cipher.init(Cipher.ENCRYPT_MODE, decryption_key);
	}
	
	/**************************************************************************
	 * ENCODE
	 **************************************************************************/
	
	public byte[] encode(String data) throws IllegalBlockSizeException, BadPaddingException {	          
	    /** Encrypt the cleartext and return the ciphertext. */
	    return encryption_cipher.doFinal(data.getBytes());
	}
	
	public byte[] encode(byte[] data) throws IllegalBlockSizeException, BadPaddingException {	          
	    /** Encrypt the cleartext and return the ciphertext. */
	    return encryption_cipher.doFinal(data);
	}
	
	/**************************************************************************
	 * DECODE
	 **************************************************************************/
	
	public byte[] decode(String data) throws IllegalBlockSizeException, BadPaddingException {	          
		/** Decrypt the ciphertext and return the cleartext. */
	    return decryption_cipher.doFinal(data.getBytes());
	}
	
	public byte[] decode(byte[] data) throws IllegalBlockSizeException, BadPaddingException {	          
		/** Decrypt the ciphertext and return the cleartext. */
	    return decryption_cipher.doFinal(data);
	}
}
