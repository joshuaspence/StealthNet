package StealthNet;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public abstract class StealthNetEntity {
	/** 
	 * Set to true in build.xml to output debug messages for this class. 
	 * Alternatively, use the argument `-Ddebug.StealthNetEntity=true' at the 
	 * command line.
	 */
	private static final boolean DEBUG = System.getProperty("debug.StealthNetEntity", "false").equals("true");
	
	private final KeyPair keys;
	private final Signature signer;
	
	private static final String KEY_ALGORITHM = "RSA";
	private static final int NUM_BITS = 1024;
	
	public StealthNetEntity() throws NoSuchAlgorithmException {
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
	
	/**************************************************************************
	 * SIGN
	 **************************************************************************/
	public byte[] sign(String data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		signer.initSign(keys.getPrivate());
		signer.update(data.getBytes());
		return signer.sign();
	}
	
	public byte[] sign(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		signer.initSign(keys.getPrivate());
		signer.update(data);
		return signer.sign();
	}
	
	/**************************************************************************
	 * VERIFY
	 **************************************************************************/
	public static boolean verify(String data, byte[] signature, PublicKey key) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		Signature signer = Signature.getInstance(KEY_ALGORITHM);
		
		signer.initVerify(key);
		signer.update(data.getBytes());
		return signer.verify(signature);
	}
	
	public static boolean verify(byte[] data, byte[] signature, PublicKey key) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		Signature signer = Signature.getInstance(KEY_ALGORITHM);
		
		signer.initVerify(key);
		signer.update(data);
		return signer.verify(signature);
	}
}