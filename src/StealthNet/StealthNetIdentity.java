package StealthNet;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * Stores identifiers for a StealthNet client or server. Generates a public key
 * and a private key to be used for authentication within StealthNet.
 * 
 * @author Joshua Spence
 */
public class StealthNetIdentity {
	/** 
	 * Set to true in build.xml to output debug messages for this class. 
	 * Alternatively, use the argument `-Ddebug.StealthNetEntity=true' at the 
	 * command line.
	 */
	private static final boolean DEBUG = System.getProperty("debug.StealthNetIdenity", "false").equals("true");
	
	/** The public/private key pair. */
	private final KeyPair keys;
	
	/** TODO */
	private final Signature signer;
	
	/** The algorithm used to generate the public/private keys. */
	private static final String KEY_ALGORITHM = "RSA";
	
	/** The number of bits of the public/private keys. */
	private static final int NUM_BITS = 1024;
	
	/**
	 * Constructor.
	 * 
	 * @throws NoSuchAlgorithmException
	 */
	public StealthNetIdentity() throws NoSuchAlgorithmException {
        /** Get the public/private key pair. */
        KeyPairGenerator keypairgen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keypairgen.initialize(NUM_BITS);
        keys = keypairgen.genKeyPair();
        
        if (DEBUG) {
        	System.out.println("Public key: \n" + keys.getPublic());
			System.out.println("Private key: \n" + keys.getPrivate());
        }
        
        signer = null;
        //signer = Signature.getInstance(KEY_ALGORITHM);
	}
	
	/**
	 * Signs a message using the private key.
	 * 
	 * @param data The message to be verified.
	 * @return The signed message.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws InvalidKeyException
	 */
	public byte[] sign(String data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		signer.initSign(keys.getPrivate());
		signer.update(data.getBytes());
		return signer.sign();
	}
	
	/**
	 * Signs a message using the private key.
	 * 
	 * @param data The message to be verified.
	 * @return The signed message.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws InvalidKeyException
	 */
	public byte[] sign(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		signer.initSign(keys.getPrivate());
		signer.update(data);
		return signer.sign();
	}
	
	/**
	 * Verifies a message using the sender's public key.
	 * 
	 * @param data The message to be verified.
	 * @param signature ???
	 * @param key The public key of the sender of the message.
	 * @return True if the message passes verification, otherwise false.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws InvalidKeyException
	 */
	public static boolean verify(String data, byte[] signature, PublicKey key) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		Signature signer = Signature.getInstance(KEY_ALGORITHM);
		
		signer.initVerify(key);
		signer.update(data.getBytes());
		return signer.verify(signature);
	}
	
	/**
	 * Verifies a message.
	 * 
	 * @param data The message to be verified.
	 * @param signature ???
	 * @param key The public key of the sender of the message.
	 * @return True if the message passes verification, otherwise false.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws InvalidKeyException
	 */
	public static boolean verify(byte[] data, byte[] signature, PublicKey key) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		Signature signer = Signature.getInstance(KEY_ALGORITHM);
		
		signer.initVerify(key);
		signer.update(data);
		return signer.verify(signature);
	}
}