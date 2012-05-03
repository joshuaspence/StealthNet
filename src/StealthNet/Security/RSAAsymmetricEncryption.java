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
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.management.InvalidAttributeValueException;

import org.apache.commons.codec.binary.Base64;

import StealthNet.EncryptedFile;

/* StealthNet.Security.AsymmetricEncryption Interface Definition *************/

/**
 * A class to provide RSA asymmetric encryption. Encryption will be performed
 * using the peer's public key. Decryption will be performed using our private
 * key. Also provides the option to save the public key to an unencrypted file
 * and the private file to a password-protected file
 *
 * @author Joshua Spence
 */
public class RSAAsymmetricEncryption extends AsymmetricEncryption {
	/** Constants describing the algorithm. */
	public static final String ALGORITHM = "RSA";
	private static final int NUM_BITS = 2048;
	private static final int MAX_CLEARTEXT = NUM_BITS / Byte.SIZE - 11;
	private static final int MAX_CIPHERTEXT = 256;

	/**
	 * Constructor to use the supplied public-private key pair.
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
	 * Constructor to use the supplied public-private key pair.
	 * 
	 * @param ourKeys Our public-private key pair.
	 * @param peer The public key of the the peer of the communications, used
	 * for encryption. If null, then encryption will be unavailable.
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
	 * Constructor to use the supplied asymmetric encryption provider. The
	 * supplied asymmetric encryption provider will be cloned except that the
	 * specified peer public key will be used.
	 * 
	 * @param ae An AsymmetricEncryption instance.
	 * @param peer The public key of the the peer of the communications, used
	 * for encryption. If null, then encryption will be unavailable.
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
	@Override
	public byte[] encrypt(final String cleartext) throws IllegalBlockSizeException, BadPaddingException {
		if (encryptionCipher == null)
			throw new IllegalStateException("Cannot perform encryption without a decryption cipher.");

		return encrypt(cleartext.getBytes());
	}

	/**
	 * Encrypts a message using the peer public key.
	 * 
	 * @param cleartext The message to be encrypted.
	 * @return The ciphertext message, encoded in base 64.
	 * 
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IllegalStateException
	 */
	@Override
	public byte[] encrypt(final byte[] cleartext) throws IllegalBlockSizeException, BadPaddingException, IllegalStateException {
		if (encryptionCipher == null)
			throw new IllegalStateException("Cannot perform encryption without a peer public key.");

		/**
		 * TODO: Tidy the following code. All that it does it break the
		 * cleartext up into 'chunks' of size MAX_CLEARTEXT, encrypt each chunk
		 * separately, and combine the chunks together.
		 */

		/**
		 * Split the cleartext up into chunks and encrypt each chunk separately.
		 */
		final Queue<byte[]> chunks = new LinkedList<byte[]>();
		int startIndex = 0;
		int totalLength = 0;

		final int chunkSize = MAX_CLEARTEXT;
		final int chunkCount = (int) Math.ceil((double) cleartext.length / (double) chunkSize);

		for (int i = 0; i < chunkCount; i++) {
			/** Get the size of the chunk. */
			byte[] chunk;
			if (startIndex + chunkSize > cleartext.length)
				chunk = new byte[cleartext.length - startIndex];
			else
				chunk = new byte[chunkSize];

			/** Copy the unencrypted chunk. */
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
	@Override
	public byte[] decrypt(final String ciphertext) throws IllegalBlockSizeException, BadPaddingException {
		if (decryptionCipher == null)
			throw new IllegalStateException("Cannot perform decryption without a decryption cipher.");

		return decrypt(ciphertext.getBytes());
	}

	/**
	 * Decrypts a message using our private key.
	 * 
	 * @param ciphertext The message to be decrypted, assumed to be encoded in
	 * base 64.
	 * @return The cleartext message.
	 * 
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	@Override
	public byte[] decrypt(final byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException {
		/** Decode the combined encrypted chunks. */
		final byte[] decodedValue = Base64.decodeBase64(ciphertext);

		/**
		 * TODO: Tidy the following code. All that it does it break the
		 * ciphertext up into 'chunks' of size MAX_CIPHERTEXT, decrypt each
		 * chunk separately, and combine the chunks together.
		 */

		/**
		 * Split the ciphertext up into chunks and decrypt each chunk separately.
		 */
		final Queue<byte[]> chunks = new LinkedList<byte[]>();
		int startIndex = 0;
		int totalLength = 0;

		final int chunkSize = MAX_CIPHERTEXT;
		final int chunkCount = (int) Math.ceil((double) decodedValue.length / (double) chunkSize);

		for (int i = 0; i < chunkCount; i++) {
			/** Get the size of the chunk. */
			byte[] chunk;
			if (startIndex + chunkSize > decodedValue.length)
				chunk = new byte[decodedValue.length - startIndex];
			else
				chunk = new byte[chunkSize];

			/** Copy the encrypted chunk. */
			System.arraycopy(decodedValue, startIndex, chunk, 0, chunk.length);
			startIndex += chunk.length;

			/** Decrypt this chunk and add it to the queue. */
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

		return combinedChunks;
	}

	/**
	 * Generate a public-private key pair.
	 * 
	 * @return A new public-private key pair,
	 * 
	 * @throws NoSuchAlgorithmException
	 */
	public static KeyPair generateKeys() throws NoSuchAlgorithmException {
		/** Initialise the key generator. */
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
		kpg.initialize(NUM_BITS);

		/** Establish the keys. */
		return kpg.genKeyPair();
	}

	/**
	 * Save the public key to a file so that it can be retrieved at a later
	 * time. The public key file will not be encrypted in any way.
	 * 
	 * @param key The public key to save.
	 * @param filename The path of the file to which the public key should be
	 * saved.
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
	 * Save the private key to a file so that it can be retrieved at a later
	 * time. The private key file will be encrypted using a user-supplied
	 * password.
	 * 
	 * @param key The private key to save.
	 * @param filename The path of the file to which the public key should be
	 * saved.
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
	 */
	public static void savePrivateKeyToFile(final PrivateKey key, final String filename, final String password) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidAttributeValueException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, IOException {
		final KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
		final RSAPrivateKeySpec keySpec = factory.getKeySpec(key, RSAPrivateKeySpec.class);
		AsymmetricEncryption.writeKeyToFile(filename, keySpec.getModulus(), keySpec.getPrivateExponent(), password);
	}

	/**
	 * Read a public key from a file.
	 * 
	 * @param filename The path to the file containing the public key.
	 * @return The public key contained within the file.
	 * 
	 * @throws IOException
	 * @throws FileNotFoundException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 */
	public static PublicKey readPublicKeyFromFile(final String filename) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		return readPublicKeyFromFile(new FileInputStream(filename));
	}

	/**
	 * Read a public key from a file.
	 * 
	 * @param file The file containing the public key.
	 * @return The public key contained within the file.
	 * 
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 */
	public static PublicKey readPublicKeyFromFile(final URL file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		return readPublicKeyFromFile(file.openStream());
	}

	/**
	 * Read the public key from a file.
	 * 
	 * @param inputStream The input stream for the file containing the public
	 * key.
	 * @return The public key contained within the file.
	 * 
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static PublicKey readPublicKeyFromFile(final InputStream inputStream) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		final BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
		final DataInputStream dataInputStream = new DataInputStream(bufferedInputStream);

		/** Get the modulus and exponent from the decrypted data. */
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

		/** Recreate the public key. */
		final RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
		final KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		final PublicKey pubKey = keyFactory.generatePublic(keySpec);

		return pubKey;
	}

	/**
	 * Read a private key from a password-encrypted file.
	 * 
	 * @param filename The path to the file containing the private key.
	 * @param password The password to decrypt the private key file.
	 * @return The private key contained within the file.
	 * 
	 * @throws IOException
	 * @throws EncryptedFileException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidKeyException
	 * @throws InvalidAttributeValueException
	 */
	public static PrivateKey readPrivateKeyFromFile(final String filename, final String password) throws InvalidAttributeValueException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, EncryptedFileException, IOException {
		return readPrivateKeyFromFile(new EncryptedFile(new File(filename), password));
	}

	/**
	 * Read a private key from a password-encrypted file.
	 * 
	 * @param file The file containing the private key.
	 * @param password The password to decrypt the file.
	 * @return The private key contained within the file.
	 * 
	 * @throws IOException
	 * @throws EncryptedFileException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidKeyException
	 * @throws InvalidAttributeValueException
	 */
	public static PrivateKey readPrivateKeyFromFile(final URL file, final String password) throws InvalidAttributeValueException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, EncryptedFileException, IOException {
		return readPrivateKeyFromFile(new EncryptedFile(file, password));
	}

	/**
	 * Read a private key from a password-encrypted file.
	 * 
	 * @param file The file containing the private key.
	 * @return The private key contained within the file.
	 * 
	 * @throws EncryptedFileException
	 * @throws NoSuchAlgorithmException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidAttributeValueException
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 */
	private static PrivateKey readPrivateKeyFromFile(final EncryptedFile file) throws InvalidAttributeValueException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, EncryptedFileException, IOException, InvalidKeySpecException {
		final byte[] decryptedData = file.decrypt();
		final ByteArrayInputStream inputStream = new ByteArrayInputStream(decryptedData);
		final BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
		final DataInputStream dataInputStream = new DataInputStream(bufferedInputStream);

		/** Get the modulus and exponent from the decrypted data. */
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

		/** Recreate the private key. */
		final RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(mod, exp);
		final KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		final PrivateKey privKey = keyFactory.generatePrivate(keySpec);

		return privKey;
	}

	/**
	 * Converts a string to a public key.
	 * 
	 * @param keyString The string representing the public key, assumed to be
	 * encoded in base 64.
	 * @return The public key represented by the input string, or null if a
	 * public key cannot be formed.
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
 * END OF FILE:     RSAAsymmetricEncryption.java
 *****************************************************************************/