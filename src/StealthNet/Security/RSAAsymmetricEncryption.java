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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/* StealthNet.Security.AsymmetricEncryption Interface Definition *************/

/**
 * TODO
 *
 * @author Joshua Spence
 */
public class RSAAsymmetricEncryption implements AsymmetricEncryption {
	private final PrivateKey privateKey;
	private final PublicKey publicKey;
	
	private final Cipher encryptionCipher;
	private final Cipher decryptionCipher;
	
	private static final String ALGORITHM = "RSA";
	private static final int NUM_BITS = 2048;
	
	/**
	 * Constructor.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException 
	 * @throws NoSuchPaddingException 
	 */
	public RSAAsymmetricEncryption() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
		kpg.initialize(NUM_BITS);
		
		final KeyPair kp = kpg.genKeyPair();
		this.publicKey = kp.getPublic();
		this.privateKey = kp.getPrivate();
		
		this.encryptionCipher = Cipher.getInstance(ALGORITHM);
		this.encryptionCipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
		
		this.decryptionCipher = Cipher.getInstance(ALGORITHM);
		this.decryptionCipher.init(Cipher.DECRYPT_MODE, this.privateKey);
	}
	
	/**
	 * Constructor.
	 * 
	 * @param publicKeyFileName
	 * @param privateKeyFileName
	 * 
	 * @throws IOException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws InvalidKeySpecException 
	 */
	public RSAAsymmetricEncryption(String publicKeyFileName, String privateKeyFileName) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
		this.publicKey = readPublicKeyFromFile(publicKeyFileName);
		this.privateKey = readPrivateKeyFromFile(privateKeyFileName);
		
		this.encryptionCipher = Cipher.getInstance(ALGORITHM);
		this.encryptionCipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
		
		this.decryptionCipher = Cipher.getInstance(ALGORITHM);
		this.decryptionCipher.init(Cipher.DECRYPT_MODE, this.privateKey);
	}
	
	/**
	 * Constructor.
	 * 
	 * @param publicKeyFile
	 * @param privateKeyFile
	 * 
	 * @throws IOException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws InvalidKeySpecException 
	 */
	public RSAAsymmetricEncryption(URL publicKeyFile, URL privateKeyFile) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
		this.publicKey = readPublicKeyFromFile(publicKeyFile);
		this.privateKey = readPrivateKeyFromFile(privateKeyFile);
		
		this.encryptionCipher = Cipher.getInstance(ALGORITHM);
		this.encryptionCipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
		
		this.decryptionCipher = Cipher.getInstance(ALGORITHM);
		this.decryptionCipher.init(Cipher.DECRYPT_MODE, this.privateKey);
	}
	
	/**
	 * TODO
	 * 
	 * @param filename
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
	 * TODO
	 * 
	 * @param filename
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
	 * TODO
	 * 
	 * @param fileName
	 * @param mod
	 * @param exp
	 * @throws IOException
	 */
	private static void writeToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
		final FileOutputStream fileOutputStream = new FileOutputStream(fileName);
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
	 * TODO
	 * 
	 * @param filename
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	private static PublicKey readPublicKeyFromFile(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		final FileInputStream fileInputStream = new FileInputStream(filename);
		final BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
		final ObjectInputStream objectInputStream = new ObjectInputStream(bufferedInputStream);
		PublicKey pubKey = null;
		
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
	    pubKey = factory.generatePublic(keySpec);
	    
		return pubKey;
	}
	
	/**
	 * TODO
	 * 
	 * @param file
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	private static PublicKey readPublicKeyFromFile(URL file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		final InputStream urlInputStream = file.openStream();
		final BufferedInputStream bufferedInputStream = new BufferedInputStream(urlInputStream);
		final ObjectInputStream objectInputStream = new ObjectInputStream(bufferedInputStream);
		PublicKey pubKey = null;
		
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
	    pubKey = factory.generatePublic(keySpec);
		
		return pubKey;
	}
	
	/**
	 * TODO
	 * 
	 * @param filename
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	private static PrivateKey readPrivateKeyFromFile(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		final FileInputStream fileInputStream = new FileInputStream(filename);
		final BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
		final ObjectInputStream objectInputStream = new ObjectInputStream(bufferedInputStream);
		PrivateKey privKey = null;
		
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
	    privKey = factory.generatePrivate(keySpec);
		
		return privKey;
	}
	
	/**
	 * TODO
	 * 
	 * @param file
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	private static PrivateKey readPrivateKeyFromFile(URL file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		final InputStream urlInputStream = file.openStream();
		final BufferedInputStream bufferedInputStream = new BufferedInputStream(urlInputStream);
		final ObjectInputStream objectInputStream = new ObjectInputStream(bufferedInputStream);
		PrivateKey privKey = null;
		
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
	    privKey = factory.generatePrivate(keySpec);
	    
		return privKey;
	}
	
	/**
	 * Encrypts a message using the decryption key.
	 * 
	 * @param cleartext The message to be encrypted.
	 * @return The ciphertext message.
	 * 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public String encrypt(String cleartext) throws IllegalBlockSizeException, BadPaddingException {
		return encrypt(cleartext.getBytes());
	}
	
	/**
	 * Encrypts a message using the public key.
	 * 
	 * @param cleartext The message to be encrypted.
	 * @return The ciphertext message.
	 * 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public String encrypt(byte[] cleartext) throws IllegalBlockSizeException, BadPaddingException {
		return new String(encryptionCipher.doFinal(cleartext));
	}
	
	/**
	 * Decrypts a message using the private key.
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
	 * Decrypts a message using the private key.
	 * 
	 * @param ciphertext The message to be decrypted.
	 * @return The cleartext message.
	 * 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public String decrypt(byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException {
		return new String(decryptionCipher.doFinal(ciphertext));
	}
	
	/**
	 * TODO
	 * 
	 * @return TODO
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}
	
	/**
	 * TODO
	 * 
	 * @return TODO
	 */
	public PrivateKey getPrivateKey() {
		return privateKey;
	}
}

/******************************************************************************
 * END OF FILE:     RSAAsymmetricEncryption.java
 *****************************************************************************/