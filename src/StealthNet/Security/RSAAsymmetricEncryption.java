/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        RSAAsymmetricEncryption.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     A class to provide RSA asymmetric encryption.
 *
 *****************************************************************************/

package StealthNet.Security;

/* Import Libraries **********************************************************/

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.LinkedList;
import java.util.Queue;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

/* StealthNet.Security.AsymmetricEncryption Interface Definition *************/

/**
 * A class to provide RSA asymmetric encryption. Encryption will be performed 
 * using the peer's public key. Decryption will be performed using our private 
 * key.
 *
 * @author Joshua Spence
 */
public class RSAAsymmetricEncryption implements AsymmetricEncryption {
	private final PrivateKey privateKey;
	private final PublicKey publicKey;
	private PublicKey peerPublicKey;
	
	private Cipher encryptionCipher;
	private final Cipher decryptionCipher;
	
	public static final String ALGORITHM = "RSA";
	public static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";
	public static final int NUM_BITS = 2048;
	
	private static final int MAX_CLEARTEXT = (NUM_BITS / Byte.SIZE) - 11;
	private static final int MAX_CIPHERTEXT = 256;
	
	/**
	 * Constructor to generate a new public/private key pair.
	 * 
	 * @param peer The public key of the peer of the communications, used for 
	 * encryption. If null, then encryption will be unavailable.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException 
	 * @throws NoSuchPaddingException 
	 */
	public RSAAsymmetricEncryption(PublicKey peer) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
		kpg.initialize(NUM_BITS);
		
		final KeyPair kp = kpg.genKeyPair();
		this.publicKey = kp.getPublic();
		this.privateKey = kp.getPrivate();
		this.peerPublicKey = peer;
		
		if (this.peerPublicKey != null) {
			this.encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
			this.encryptionCipher.init(Cipher.ENCRYPT_MODE, this.peerPublicKey);
		} else {
			this.encryptionCipher = null;
		}
		
		this.decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
		this.decryptionCipher.init(Cipher.DECRYPT_MODE, this.privateKey);
	}
	
	/**
	 * Constructor to read our public and private keys from a file.
	 * 
	 * @param publicKeyFileName The path to the file containing our public key.
	 * @param privateKeyFileName The path to the file containing our private 
	 * key.
	 * @param peer The public key of the the peer of the communications, used 
	 * for encryption. If null, then encryption will be unavailable.
	 * 
	 * @throws IOException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws InvalidKeySpecException 
	 */
	public RSAAsymmetricEncryption(String publicKeyFileName, String privateKeyFileName, PublicKey peer) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
		this.publicKey = readPublicKeyFromFile(publicKeyFileName);
		this.privateKey = readPrivateKeyFromFile(privateKeyFileName);
		this.peerPublicKey = peer;
		
		if (this.peerPublicKey != null) {
			this.encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
			this.encryptionCipher.init(Cipher.ENCRYPT_MODE, this.peerPublicKey);
		} else {
			this.encryptionCipher = null;
		}
		
		this.decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
		this.decryptionCipher.init(Cipher.DECRYPT_MODE, this.privateKey);
	}
	
	/**
	 * Constructor to read our public and private keys from a file.
	 * 
	 * @param publicKeyFile The file containing our public key.
	 * @param privateKeyFile The file containing our private key. 
	 * @param peer The public key of the the peer of the communications, used 
	 * for encryption. If null, then encryption will be unavailable.
	 * 
	 * @throws IOException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws InvalidKeySpecException 
	 */
	public RSAAsymmetricEncryption(URL publicKeyFile, URL privateKeyFile, PublicKey peer) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
		this.publicKey = readPublicKeyFromFile(publicKeyFile);
		this.privateKey = readPrivateKeyFromFile(privateKeyFile);
		this.peerPublicKey = peer;
		
		if (this.peerPublicKey != null) {
			this.encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
			this.encryptionCipher.init(Cipher.ENCRYPT_MODE, this.peerPublicKey);
		} else {
			this.encryptionCipher = null;
		}
		
		this.decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
		this.decryptionCipher.init(Cipher.DECRYPT_MODE, this.privateKey);
	}
	
	/**
	 * Constructor to use the supplied public/private key pair.
	 * 
	 * @param publicKey Our public key.
	 * @param privateKey Our private key. 
	 * @param peer The public key of the the peer of the communications, used 
	 * for encryption. If null, then encryption will be unavailable.
	 * 
	 * @throws IOException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws InvalidKeySpecException 
	 */
	public RSAAsymmetricEncryption(PublicKey publicKey, PrivateKey privateKey, PublicKey peer) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
		this.peerPublicKey = peer;
		
		if (this.peerPublicKey != null) {
			this.encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
			this.encryptionCipher.init(Cipher.ENCRYPT_MODE, this.peerPublicKey);
		} else {
			this.encryptionCipher = null;
		}
		
		this.decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
		this.decryptionCipher.init(Cipher.DECRYPT_MODE, this.privateKey);
	}
	
	/**
	 * Constructor to use the supplied asymmetric encryption provider. The 
	 * supplied asymmetric encryption provider will be cloned except that the 
	 * specified peer public key will be used,
	 * 
	 * @param ae An AsymmetricEncryption instance.
	 * @param peer The public key of the the peer of the communications, used 
	 * for encryption. If null, then encryption will be unavailable.
	 * 
	 * @throws IOException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws InvalidKeySpecException 
	 */
	public RSAAsymmetricEncryption(AsymmetricEncryption ae, PublicKey peer) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
		this.publicKey = ae.getPublicKey();
		this.privateKey = ae.getPrivateKey();
		this.peerPublicKey = peer;
		
		if (this.peerPublicKey != null) {
			this.encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
			this.encryptionCipher.init(Cipher.ENCRYPT_MODE, this.peerPublicKey);
		} else {
			this.encryptionCipher = null;
		}
		
		this.decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
		this.decryptionCipher.init(Cipher.DECRYPT_MODE, this.privateKey);
	}
	
	/**
	 * Save the public key to a file so that it can be retrieved at a later 
	 * time.
	 * 
	 * @param filename The path of the file to which the public key should be 
	 * saved.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	public void savePublicKeyToFile(String filename) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		final KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
		final RSAPublicKeySpec pub = factory.getKeySpec(this.publicKey, RSAPublicKeySpec.class);
		writeToFile(filename, pub.getModulus(), pub.getPublicExponent());
	}
	
	/**
	 * Save the private key to a file so that it can be retrieved at a later 
	 * time.
	 * 
	 * @param filename The path of the file to which the public key should be 
	 * saved.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	public void savePrivateKeyToFile(String filename) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		final KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
		final RSAPrivateKeySpec priv = factory.getKeySpec(this.privateKey, RSAPrivateKeySpec.class);
		writeToFile(filename, priv.getModulus(), priv.getPrivateExponent());
	}
	
	/**
	 * A utility function to write the modulus and exponent of a key to a file.
	 * 
	 * @param filename The path of the file to write to.
	 * @param mod The modulus of the key.
	 * @param exp The exponent of the key.
	 * 
	 * @throws IOException
	 */
	private static void writeToFile(String filename, BigInteger mod, BigInteger exp) throws IOException {
		final FileOutputStream fileOutputStream = new FileOutputStream(filename);
		final BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream);
		final ObjectOutputStream objectOutputStream = new ObjectOutputStream(bufferedOutputStream);
  
		try {
			objectOutputStream.writeObject(mod);
			objectOutputStream.writeObject(exp);
		} catch (Exception e) {
			throw new IOException("Unexpected error", e);
		} finally {
			objectOutputStream.close();
		}
	}
	
	/**
	 * Read the public key from a file.
	 * 
	 * @param filename The path to the file containing the public key.
	 * @return The public key contained within the file.
	 * 
	 * @throws IOException
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public static PublicKey readPublicKeyFromFile(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		final FileInputStream fileInputStream = new FileInputStream(filename);
		final BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
		final ObjectInputStream objectInputStream = new ObjectInputStream(bufferedInputStream);
		
		BigInteger mod, exp;
		try {
		    mod = (BigInteger) objectInputStream.readObject();
		    exp = (BigInteger) objectInputStream.readObject();
		} catch (Exception e) {
		    throw new RuntimeException("Spurious serialisation error", e);
		} finally {
			objectInputStream.close();
		}
		
		final RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
	    final KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
	    final PublicKey pubKey = factory.generatePublic(keySpec);
	    
		return pubKey;
	}
	
	/**
	 * Read the public key from a file.
	 * 
	 * @param file The file containing the public key.
	 * @return The public key contained within the file.
	 * 
	 * @throws IOException
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public static PublicKey readPublicKeyFromFile(URL file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		final InputStream urlInputStream = file.openStream();
		final BufferedInputStream bufferedInputStream = new BufferedInputStream(urlInputStream);
		final ObjectInputStream objectInputStream = new ObjectInputStream(bufferedInputStream);
		
		BigInteger mod, exp;
		try {
		    mod = (BigInteger) objectInputStream.readObject();
		    exp = (BigInteger) objectInputStream.readObject();
		} catch (Exception e) {
		    throw new RuntimeException("Spurious serialisation error", e);
		} finally {
			objectInputStream.close();
		}
		
		final RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
	    final KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
	    final PublicKey pubKey = factory.generatePublic(keySpec);
		
		return pubKey;
	}
	
	/**
	 * Read the private key from a file.
	 * 
	 * @param filename The path to the file containing the private key.
	 * @return The private key contained within the file.
	 * 
	 * @throws IOException
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	private static PrivateKey readPrivateKeyFromFile(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		final FileInputStream fileInputStream = new FileInputStream(filename);
		final BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
		final ObjectInputStream objectInputStream = new ObjectInputStream(bufferedInputStream);
		
		BigInteger mod, exp;
		try {
		    mod = (BigInteger) objectInputStream.readObject();
		    exp = (BigInteger) objectInputStream.readObject();
		} catch (Exception e) {
		    throw new RuntimeException("Spurious serialisation error", e);
		} finally {
			objectInputStream.close();
		}
		
		final RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(mod, exp);
	    final KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
	    final PrivateKey privKey = factory.generatePrivate(keySpec);
		
		return privKey;
	}
	
	/**
	 * Read the private key from a file.
	 * 
	 * @param file The file containing the private key.
	 * @return The private key contained within the file.
	 * 
	 * @throws IOException
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	private static PrivateKey readPrivateKeyFromFile(URL file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		final InputStream urlInputStream = file.openStream();
		final BufferedInputStream bufferedInputStream = new BufferedInputStream(urlInputStream);
		final ObjectInputStream objectInputStream = new ObjectInputStream(bufferedInputStream);
		
		BigInteger mod, exp;
		try {
		    mod = (BigInteger) objectInputStream.readObject();
		    exp = (BigInteger) objectInputStream.readObject();
		    
		} catch (Exception e) {
		    throw new RuntimeException("Spurious serialisation error", e);
		} finally {
			objectInputStream.close();
		}
		
		final RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(mod, exp);
	    final KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
	    final PrivateKey privKey = factory.generatePrivate(keySpec);
	    
		return privKey;
	}
	
	/**
	 * Encrypts a message using the peer public key. If the cleartext is longer
	 * than the maximum allowable cleartext (MAX_CLEARTEXT), then the cleartext 
	 * will be encrypted in chunks of length MAX_CLEARTEXT.
	 * 
	 * @param cleartext The message to be encrypted.
	 * @return The ciphertext message.
	 * 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws IllegalStateException
	 */
	public String encrypt(String cleartext) throws IllegalBlockSizeException, BadPaddingException, IllegalStateException {
		return encrypt(cleartext.getBytes());
	}
	
	/**
	 * Encrypts a message using the peer public key. If the cleartext is longer
	 * than the maximum allowable cleartext (MAX_CLEARTEXT), then the cleartext
	 * will be encrypted in chunks of length MAX_CLEARTEXT.
	 * 
	 * @param cleartext The message to be encrypted.
	 * @return The ciphertext message.
	 * 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws IllegalStateException
	 */
	public String encrypt(byte[] cleartext) throws IllegalBlockSizeException, BadPaddingException, IllegalStateException {
		if (encryptionCipher == null)
			throw new IllegalStateException("Cannot perform encryption without a peer public key.");
		
		/** 
		 * Split the cleartext up into chunks and encrypt each chunk separately.
		 */
    	final Queue<byte[]> chunks = new LinkedList<byte[]>();
    	int startIndex = 0;
    	int totalLength = 0;
    	final int chunkCount = (int) Math.ceil((double) cleartext.length / (double) MAX_CLEARTEXT);
    	for (int i = 0; i < chunkCount; i++) {
    		byte[] chunk;
    		if (startIndex + MAX_CLEARTEXT > cleartext.length)
    			chunk = new byte[cleartext.length - startIndex];
    		else
    			chunk = new byte[MAX_CLEARTEXT];
    		
    		System.arraycopy(cleartext, startIndex, chunk, 0, chunk.length);
    		startIndex += chunk.length;

    		/** Encrypt this chunk and add it to the queue. */
    		final byte[] encryptedChunk = encryptionCipher.doFinal(chunk);
    		chunks.add(encryptedChunk);
    		totalLength += encryptedChunk.length;
    	}
    	
    	/** Combine the encrypted chunks. */
    	int currentIndex = 0;
    	final byte[] combinedChunks = new byte[totalLength];
    	while (chunks.size() > 0) {
    		final byte[] chunk = chunks.remove();
    		System.arraycopy(chunk, 0, combinedChunks, currentIndex, chunk.length);
    		currentIndex += chunk.length;
        }
		
    	/** Encode the combined encrypted chunks. */
        final byte[] encodedValue = Base64.encodeBase64(combinedChunks);
        return new String(encodedValue);
	}
	
	/**
	 * Decrypts a message using our private key.
	 * 
	 * @param ciphertext The message to be decrypted.
	 * @return The cleartext message.
	 * 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public String decrypt(String ciphertext) throws IllegalBlockSizeException, BadPaddingException {
		return decrypt(ciphertext.getBytes());
	}
	
	/**
	 * Decrypts a message using our private key.
	 * 
	 * @param ciphertext The message to be decrypted.
	 * @return The cleartext message.
	 * 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public String decrypt(byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException {
		/** Decode the combined encrypted chunks. */
		final byte[] decodedValue = Base64.decodeBase64(ciphertext);
		
		/** 
		 * Split the ciphertext up into chunks and decrypt each chunk separately.
		 */
    	final Queue<byte[]> chunks = new LinkedList<byte[]>();
    	int startIndex = 0;
    	int totalLength = 0;
    	final int chunkCount = (int) Math.ceil((double) decodedValue.length / (double) MAX_CIPHERTEXT);
    	for (int i = 0; i < chunkCount; i++) {
    		byte[] chunk;
    		if (startIndex + MAX_CIPHERTEXT > decodedValue.length)
    			chunk = new byte[decodedValue.length - startIndex];
    		else
    			chunk = new byte[MAX_CIPHERTEXT];
    		
    		System.arraycopy(decodedValue, startIndex, chunk, 0, chunk.length);
    		startIndex += chunk.length;

    		/** Encrypt this chunk and add it to the queue. */
    		final byte[] decryptedChunk = decryptionCipher.doFinal(chunk);
    		chunks.add(decryptedChunk);
    		totalLength += decryptedChunk.length;
    	}
    	
    	/** Combine the decrypted chunks. */
    	int currentIndex = 0;
    	final byte[] combinedChunks = new byte[totalLength];
    	while (chunks.size() > 0) {
    		final byte[] chunk = chunks.remove();
    		System.arraycopy(chunk, 0, combinedChunks, currentIndex, chunk.length);
    		currentIndex += chunk.length;
        }
    	
        return new String(combinedChunks);
	}
	
	/**
	 * Get our public key.
	 * 
	 * @return Our public key.
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}
	
	/**
	 * Get the peer's public key. The peer's public key is used for encryption.
	 * 
	 * @return The peer's public key.
	 */
	public PublicKey getPeerPublicKey() {
		return peerPublicKey;
	}
	
	/**
	 * Set the peer's public key. The peer's public key is used for encryption.
	 * 
	 * @param peer The peer's public key.
	 * 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public void setPeerPublicKey(PublicKey peer) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		this.peerPublicKey = peer;
		
		if (this.peerPublicKey != null) {
			this.encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
			this.encryptionCipher.init(Cipher.ENCRYPT_MODE, this.peerPublicKey);
		} else {
			this.encryptionCipher = null;
		}
	}
	
	/**
	 * Get our private key. Our private key is used for decryption.
	 * 
	 * @return Our private key.
	 */
	public PrivateKey getPrivateKey() {
		return privateKey;
	}
}

/******************************************************************************
 * END OF FILE:     RSAAsymmetricEncryption.java
 *****************************************************************************/