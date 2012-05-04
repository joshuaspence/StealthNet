/* @formatter:off */
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
/* @formatter:on */

package StealthNet.Security;

/* Import Libraries ******************************************************** */

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
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
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedList;
import java.util.Queue;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.management.InvalidAttributeValueException;

import org.apache.commons.codec.binary.Base64;

import StealthNet.EncryptedFile;

/* StealthNet.Security.AsymmetricEncryption Interface Definition *********** */

/**
 * A class to provide RSA asymmetric encryption. Encryption will be performed
 * using the peer's {@link PublicKey}. Decryption will be performed using our
 * {@link PrivateKey}. Also provides the option to save the {@link PublicKey} to
 * an unencrypted file and the {@link PrivateKey} to a password-protected file.
 * 
 * @author Joshua Spence
 * @see AsymmetricEncryption
 * @see Encryption
 */
public class RSAAsymmetricEncryption extends AsymmetricEncryption {
	/**
	 * The algorithm to be used for the encryption and decryption {@link Cipher}
	 * .
	 */
	public static final String ALGORITHM = "RSA";
	
	/** The number of bits to use for the encryption and decryption keys. */
	private static final int NUM_BITS = 2048;
	
	/**
	 * The maximum length of a chunk of cleartext. Data to be encoded will be
	 * broken up into chunks of this size and encoded separately.
	 */
	private static final int MAX_CLEARTEXT = NUM_BITS / Byte.SIZE - 11;
	
	/**
	 * The length of a chunk of ciphertext produced by the encryption
	 * {@link Cipher}. Should be constant regardless of the size of the
	 * cleartext input.
	 * 
	 * Data to be decoded will be broken up into chunks of this size and decoded
	 * seperately.
	 */
	private static final int MAX_CIPHERTEXT = 256;
	
	/**
	 * Constructor to use the supplied public-private {@link KeyPair} for
	 * decryption. Encryption will not yet be enabled.
	 * 
	 * @param ourKeys Our public-private key pair.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public RSAAsymmetricEncryption(final KeyPair ourKeys) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		super(ALGORITHM, ourKeys);
	}
	
	/**
	 * Constructor to use the supplied public-private {@link KeyPair} for
	 * decryption and the supplied peer {@link PublicKey} for encryption.
	 * 
	 * @param ourKeys Our public-private {@link KeyPair}
	 * @param peer The {@link PublicKey} of the the peer of the communications,
	 *        used for encryption. If null, then encryption will be unavailable.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public RSAAsymmetricEncryption(final KeyPair ourKeys, final PublicKey peer) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		super(ALGORITHM, ourKeys);
		super.setPeerPublicKey(peer);
	}
	
	/**
	 * Constructor to use the supplied {@link AsymmetricEncryption} provider.
	 * The supplied {@link AsymmetricEncryption} provider will be cloned except
	 * that the specified peer {@link PublicKey} will be used.
	 * 
	 * @param ae An {@link AsymmetricEncryption} instance.
	 * @param peer The {@link PublicKey} of the the peer of the communications,
	 *        used for encryption. If null, then encryption will be unavailable.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public RSAAsymmetricEncryption(final AsymmetricEncryption ae, final PublicKey peer) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		super(ALGORITHM, ae.getKeys());
		super.setPeerPublicKey(peer);
	}
	
	/**
	 * Encrypts the given data using the peer {@link PublicKey}. Performs the
	 * opposite of the <code>decrypt(String)</code> function.
	 * 
	 * @param cleartext The data to encrypt.
	 * @return The encrypted data, encoded in base-64.
	 * 
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IllegalStateException If the encryption cipher hasn't been set.
	 * @see Base64
	 */
	@Override
	public byte[] encrypt(final String cleartext) throws IllegalBlockSizeException, BadPaddingException {
		if (encryptionCipher == null)
			throw new IllegalStateException("Cannot perform encryption without a peer public key.");
		
		return encrypt(cleartext.getBytes());
	}
	
	/**
	 * Encrypts the given data using the peer {@link PublicKey}. Performs the
	 * opposite of the <code>decrypt(byte[])</code< function.
	 * 
	 * @param cleartext The data to be encrypted.
	 * @return The ciphertext message, encoded in base-64.
	 * 
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IllegalStateException
	 * @throws IllegalStateException If the encryption cipher hasn't been set.
	 * @see Base64
	 */
	@Override
	public byte[] encrypt(final byte[] cleartext) throws IllegalBlockSizeException, BadPaddingException, IllegalStateException {
		if (encryptionCipher == null)
			throw new IllegalStateException("Cannot perform encryption without a peer public key.");
		
		/*
		 * TODO: Tidy the following code. All that it does it break the
		 * cleartext up into 'chunks' of size MAX_CLEARTEXT, encrypt each chunk
		 * separately, and combine the chunks together.
		 * 
		 * This should *ideally* be done automatically by the cipher.
		 */
		
		/*
		 * Split the cleartext up into chunks and encrypt each chunk separately.
		 */
		final Queue<byte[]> chunks = new LinkedList<byte[]>();
		int startIndex = 0;
		int totalLength = 0;
		
		final int chunkSize = MAX_CLEARTEXT;
		final int chunkCount = (int) Math.ceil((double) cleartext.length / (double) chunkSize);
		
		for (int i = 0; i < chunkCount; i++) {
			/* Get the size of the chunk. */
			byte[] chunk;
			if (startIndex + chunkSize > cleartext.length)
				chunk = new byte[cleartext.length - startIndex];
			else
				chunk = new byte[chunkSize];
			
			/* Copy the unencrypted chunk. */
			System.arraycopy(cleartext, startIndex, chunk, 0, chunk.length);
			startIndex += chunk.length;
			
			/* Encrypt this chunk and add it to the queue. */
			final byte[] encryptedChunk = encryptionCipher.doFinal(chunk);
			chunks.add(encryptedChunk);
			totalLength += encryptedChunk.length;
		}
		
		/* Combine the encrypted chunks. */
		int currentIndex = 0;
		final byte[] combinedChunks = new byte[totalLength];
		while (chunks.size() > 0) {
			final byte[] chunk = chunks.remove();
			System.arraycopy(chunk, 0, combinedChunks, currentIndex, chunk.length);
			currentIndex += chunk.length;
		}
		
		/* Encode the combined encrypted chunks in base-64. */
		final byte[] encodedValue = Base64.encodeBase64(combinedChunks);
		return encodedValue;
	}
	
	/**
	 * Decrypts the given data using our {@link PrivateKey}. Performs the
	 * opposite of the <code>encrypt(String)</code< function.
	 * 
	 * @param ciphertext The data to be decrypted, assumed to be encoded in
	 *        base-64.
	 * @return The cleartext message.
	 * 
	 * @throws UnsupportedEncodingException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IllegalStateException If the encryption cipher hasn't been set.
	 * @see Base64
	 */
	@Override
	public byte[] decrypt(final String ciphertext) throws IllegalBlockSizeException, BadPaddingException {
		if (decryptionCipher == null)
			throw new IllegalStateException("Cannot perform decryption without a decryption cipher.");
		
		return decrypt(ciphertext.getBytes());
	}
	
	/**
	 * Decrypts the given data using our {@link PrivateKey}. Performs the
	 * opposite of the <code>encrypt(byte[])</code< function.
	 * 
	 * @param ciphertext The message to be decrypted, assumed to be encoded in
	 *        base 64.
	 * @return The cleartext message.
	 * 
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IllegalStateException If the encryption cipher hasn't been set.
	 * @see Base64
	 */
	@Override
	public byte[] decrypt(final byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException {
		/* Decode the combined encrypted chunks. */
		final byte[] decodedValue = Base64.decodeBase64(ciphertext);
		
		/*
		 * TODO: Tidy the following code. All that it does it break the
		 * ciphertext up into 'chunks' of size MAX_CIPHERTEXT, decrypt each
		 * chunk separately, and combine the chunks together.
		 * 
		 * This should *ideally* be done automatically by the cipher.
		 */
		
		/*
		 * Split the ciphertext up into chunks and decrypt each chunk
		 * separately.
		 */
		final Queue<byte[]> chunks = new LinkedList<byte[]>();
		int startIndex = 0;
		int totalLength = 0;
		
		final int chunkSize = MAX_CIPHERTEXT;
		final int chunkCount = (int) Math.ceil((double) decodedValue.length / (double) chunkSize);
		
		for (int i = 0; i < chunkCount; i++) {
			/* Get the size of the chunk. */
			byte[] chunk;
			if (startIndex + chunkSize > decodedValue.length)
				chunk = new byte[decodedValue.length - startIndex];
			else
				chunk = new byte[chunkSize];
			
			/* Copy the encrypted chunk. */
			System.arraycopy(decodedValue, startIndex, chunk, 0, chunk.length);
			startIndex += chunk.length;
			
			/* Decrypt this chunk and add it to the queue. */
			final byte[] decryptedChunk = decryptionCipher.doFinal(chunk);
			chunks.add(decryptedChunk);
			totalLength += decryptedChunk.length;
		}
		
		/* Combine the decrypted chunks. */
		int currentIndex = 0;
		final byte[] combinedChunks = new byte[totalLength];
		while (chunks.size() > 0) {
			final byte[] chunk = chunks.remove();
			System.arraycopy(chunk, 0, combinedChunks, currentIndex, chunk.length);
			currentIndex += chunk.length;
		}
		
		return combinedChunks;
	}
	
	/**
	 * Generate a public-private {@link KeyPair}.
	 * 
	 * @return A new public-private {@link KeyPair}
	 * 
	 * @throws NoSuchAlgorithmException
	 */
	public static KeyPair generateKeys() throws NoSuchAlgorithmException {
		/* Initialise the key generator. */
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
		kpg.initialize(NUM_BITS);
		
		/* Establish the keys. */
		return kpg.genKeyPair();
	}
	
	/**
	 * Save the {@link PublicKey} to a file so that it can be retrieved at a
	 * later time. The {@link PublicKey} file will not be encrypted in any way.
	 * 
	 * @param key The public key to save.
	 * @param filename The path of the file to which the {@link PublicKey}
	 *        should be saved.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidAttributeValueException
	 * @throws InvalidKeyException
	 */
	public static void savePublicKeyToFile(final PublicKey key, final String filename) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidAttributeValueException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, IOException {
		final KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
		final RSAPublicKeySpec keySpec = factory.getKeySpec(key, RSAPublicKeySpec.class);
		AsymmetricEncryption.writeKeyToFile(filename, keySpec.getModulus(), keySpec.getPublicExponent(), null);
	}
	
	/**
	 * Save the {@link PrivateKey} to a file so that it can be retrieved at a
	 * later time. The {@link PrivateKey} file will be encrypted using a
	 * user-supplied password.
	 * 
	 * @param key The {@link PrivateKey} to save.
	 * @param filename The path of the file to which the {@link PrivateKey}
	 *        should be saved.
	 * @param password The password to encrypt the file.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidAttributeValueException
	 * @throws InvalidKeyException
	 * 
	 * @see PasswordEncryption
	 * @see EncryptedFile
	 */
	public static void savePrivateKeyToFile(final PrivateKey key, final String filename, final String password) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidAttributeValueException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, IOException {
		final KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
		final RSAPrivateKeySpec keySpec = factory.getKeySpec(key, RSAPrivateKeySpec.class);
		AsymmetricEncryption.writeKeyToFile(filename, keySpec.getModulus(), keySpec.getPrivateExponent(), password);
	}
	
	/**
	 * Read a {@link PublicKey} from a file.
	 * 
	 * @param filename The path to the file containing the {@link PublicKey}.
	 * @return The {@link PublicKey} contained within the file.
	 * 
	 * @throws IOException
	 * @throws FileNotFoundException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @see FileInputStream
	 */
	public static PublicKey readPublicKeyFromFile(final String filename) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		return readPublicKeyFromFile(new FileInputStream(filename));
	}
	
	/**
	 * Read a {@link PublicKey} from a file.
	 * 
	 * @param file The file containing the {@link PublicKey}.
	 * @return The {@link PublicKey} contained within the file.
	 * 
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @see URL
	 * @see InputStream
	 */
	public static PublicKey readPublicKeyFromFile(final URL file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		return readPublicKeyFromFile(file.openStream());
	}
	
	/**
	 * Read the {@link PublicKey} from a file.
	 * 
	 * @param inputStream The {@link InputStream} for the file containing the
	 *        public key.
	 * @return The {@link PublicKey} contained within the file.
	 * 
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @see InputStream
	 */
	private static PublicKey readPublicKeyFromFile(final InputStream inputStream) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		final BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
		final DataInputStream dataInputStream = new DataInputStream(bufferedInputStream);
		
		/* Get the modulus and exponent of the key from the decrypted data. */
		BigInteger mod = null;
		BigInteger exp = null;
		try {
			final int modBytes = dataInputStream.readInt();
			final byte[] modByteArray = new byte[modBytes];
			dataInputStream.read(modByteArray);
			mod = new BigInteger(modByteArray);
			
			final int expBytes = dataInputStream.readInt();
			final byte[] expByteArray = new byte[expBytes];
			dataInputStream.read(expByteArray);
			exp = new BigInteger(expByteArray);
		} catch (final Exception e) {
			throw new IOException("Unexpected error", e);
		} finally {
			dataInputStream.close();
			bufferedInputStream.close();
		}
		
		/* Recreate the public key from the modulus and exponent. */
		final RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
		final KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		final PublicKey pubKey = keyFactory.generatePublic(keySpec);
		
		return pubKey;
	}
	
	/**
	 * Read a {@link PrivateKey} from a password-encrypted file.
	 * 
	 * @param filename The path to the file containing the {@link PrivateKey}.
	 * @param password The password to decrypt the {@link PrivateKey} file.
	 * @return The {@link PrivateKey} contained within the file. If the
	 *         {@link PrivateKey} file is corrupt or the user supplied
	 * 
	 * @throws IOException
	 * @throws EncryptedFileException Thrown if the {@link PrivateKey} file is
	 *         corrupt, or if an incorrect password was supplied.
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidKeyException
	 * @throws InvalidAttributeValueException
	 * 
	 * @see PasswordEncryption
	 * @see EncryptedFile
	 */
	public static PrivateKey readPrivateKeyFromFile(final String filename, final String password) throws InvalidAttributeValueException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, EncryptedFileException, IOException {
		return readPrivateKeyFromFile(new EncryptedFile(new File(filename), password));
	}
	
	/**
	 * Read a {@link PrivateKey} from a password-encrypted file.
	 * 
	 * @param file The file containing the {@link PrivateKey}.
	 * @param password The password to decrypt the file.
	 * @return The {@link PrivateKey} contained within the file.
	 * 
	 * @throws IOException
	 * @throws EncryptedFileException Thrown if the {@link PrivateKey} file is
	 *         corrupt, or if an incorrect password was supplied.
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidKeyException
	 * @throws InvalidAttributeValueException
	 * 
	 * @see PasswordEncryption
	 * @see EncryptedFile
	 */
	public static PrivateKey readPrivateKeyFromFile(final URL file, final String password) throws InvalidAttributeValueException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, EncryptedFileException, IOException {
		return readPrivateKeyFromFile(new EncryptedFile(file, password));
	}
	
	/**
	 * Read a {@link PrivateKey} from a password-encrypted file.
	 * 
	 * @param file The file containing the {@link PrivateKey}.
	 * @return The {@link PrivateKey} contained within the file.
	 * 
	 * @throws EncryptedFileException Thrown if the {@link PrivateKey} file is
	 *         corrupt, or if an incorrect password was supplied.
	 * @throws NoSuchAlgorithmException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidAttributeValueException
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 * 
	 * @see PasswordEncryption
	 * @see EncryptedFile
	 */
	private static PrivateKey readPrivateKeyFromFile(final EncryptedFile file) throws InvalidAttributeValueException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, EncryptedFileException, IOException, InvalidKeySpecException {
		final byte[] decryptedData = file.decrypt();
		final ByteArrayInputStream inputStream = new ByteArrayInputStream(decryptedData);
		final BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
		final DataInputStream dataInputStream = new DataInputStream(bufferedInputStream);
		
		/* Get the modulus and exponent of the key from the decrypted data. */
		BigInteger mod = null;
		BigInteger exp = null;
		try {
			final int modBytes = dataInputStream.readInt();
			final byte[] modByteArray = new byte[modBytes];
			dataInputStream.read(modByteArray);
			mod = new BigInteger(modByteArray);
			
			final int expBytes = dataInputStream.readInt();
			final byte[] expByteArray = new byte[expBytes];
			dataInputStream.read(expByteArray);
			exp = new BigInteger(expByteArray);
		} catch (final Exception e) {
			throw new IOException("Unexpected error", e);
		} finally {
			dataInputStream.close();
			bufferedInputStream.close();
			inputStream.close();
		}
		
		/* Recreate the private key from the modulus and exponent. */
		final RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(mod, exp);
		final KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		final PrivateKey privKey = keyFactory.generatePrivate(keySpec);
		
		return privKey;
	}
	
	/**
	 * Converts a {@link String} to a {@link PublicKey}
	 * 
	 * @param keyString The string representing the {@link PublicKey}, assumed
	 *        to be encoded in base-64.
	 * @return The {@link PublicKey} represented by the input string, or null if
	 *         a {@link PublicKey} cannot be formed.
	 * @see Base64
	 */
	public static PublicKey stringToPublicKey(final String keyString) {
		try {
			final KeyFactory factory = KeyFactory.getInstance(RSAAsymmetricEncryption.ALGORITHM);
			final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(keyString));
			return factory.generatePublic(keySpec);
		} catch (final Exception e) {
			return null;
		}
	}
}

/******************************************************************************
 * END OF FILE: RSAAsymmetricEncryption.java
 *****************************************************************************/
