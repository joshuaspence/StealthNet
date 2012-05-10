/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie, Stephen Gould and Ryan Junee
 *
 * PACKAGE:         StealthNet
 * FILENAME:        CryptoCreditHashChain.java
 * AUTHORS:         Joshua Spence and James Dimitrios Moutafidis
 * DESCRIPTION:     Implementation of the StealthNet CryptoCreditHashChain 
 * 					class.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet;

/* Import Libraries ******************************************************** */

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Stack;

import org.apache.commons.codec.binary.Base64;

import StealthNet.Security.AsymmetricVerification;

/* StealthNet.CryptoCreditHashChain Class Definition *********************** */

/**
 * A class to provide a currency system for the StealthNet system. A
 * CryptoCredit is a hash, produced by a {@link MessageDigest} algorithm, and a
 * {@link Stack} of CryptoCredits forms a CryptoCreditHashChain.
 * 
 * TODO: Write more detail here.
 * 
 * @author Joshua Spence
 * @author James Dimitrios Moutafidis
 */
public class CryptoCreditHashChain {
	/* Debug options. */
	private static final boolean DEBUG_GENERAL = Debug.isDebug("StealthNet.CryptoCreditHashChain.General");
	private static final boolean DEBUG_ERROR_TRACE = Debug.isDebug("StealthNet.CryptoCreditHashChain.ErrorTrace") || Debug.isDebug("ErrorTrace");
	
	/** Algorithm to use for the hash chain {@link MessageDigest}. */
	private static final String HASH_ALGORITHM = "MD5";
	
	/** The number of (random) bytes to use as a seed for the hash chain. */
	private static final int HASHCHAIN_SEED_BYTES = 8;
	
	/** Class to represent individual credits. */
	public class CryptoCredit {
		byte[] hash = null;
	}
	
	/** {@link Stack} to store the hash chain. */
	private final Stack<CryptoCredit> hashChain;
	
	/**
	 * The tuple that the {@link Bank} needs to sign to validate this hash
	 * chain.
	 */
	private final byte[] bankIdentifier;
	
	/** The signature provided by the {@link Bank} for the hash chain. */
	private byte[] bankSignature = null;
	
	/** Constructor to generate an empty hash chain. */
	public CryptoCreditHashChain() {
		hashChain = new Stack<CryptoCredit>();
		bankIdentifier = null;
		bankSignature = null;
	}
	
	/**
	 * Constructor to generate a new hash chain.
	 * 
	 * @param username The username of the user that generated the hash chain.
	 * @param credits An integer indicating the number of credits stored in the
	 *        hash chain.
	 */
	public CryptoCreditHashChain(final String username, final int credits) {
		hashChain = generateHashChain(credits + 1);
		
		/* Construct the identifying tuple that the bank will need to sign. */
		final Stack<byte[]> topOfStack = getNextCredits(1);
		bankIdentifier = generateIdentifyingTuple(username, credits, topOfStack.peek());
	}
	
	/**
	 * Request that the bank signs this hash chain, storing the signature for
	 * later use.
	 * 
	 * @param bankComms The {@link Comms} class to communicate with the
	 *        {@link Bank}.
	 * @return True if the {@link Bank} signed the hash chain, otherwise false.
	 */
	public boolean getSigned(final Comms bankComms) {
		bankSignature = getBankSignature(bankComms, bankIdentifier);
		return bankSignature != null;
	}
	
	/**
	 * Retrieves the identifier used by the {@link Bank} to identify the hash
	 * chain.
	 * 
	 * @return The identifier used by the {@link Bank}.
	 */
	public byte[] getIdentifier() {
		return bankIdentifier;
	}
	
	/**
	 * Retrieves the signature provided by the bank. The
	 * <code>getSigned(Comms)</code> function must be called before this
	 * function.
	 * 
	 * @return The signature provided by the {@link Bank}, or null if no such
	 *         signature exists.
	 */
	public byte[] getSignature() {
		return bankSignature;
	}
	
	/**
	 * Retrieves the identifier and the signature.
	 * 
	 * @return An array containing the identifier and the signature.
	 */
	public byte[] getIdentifierAndSignture() {
		byte[] data = null;
		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		final DataOutputStream dataOutput = new DataOutputStream(output);
		try {
			dataOutput.writeInt(bankIdentifier.length);
			dataOutput.write(bankIdentifier);
			dataOutput.writeInt(bankSignature.length);
			dataOutput.write(bankSignature);
			
			dataOutput.flush();
			output.flush();
			data = output.toByteArray();
			dataOutput.close();
			output.close();
		} catch (final Exception e) {
			System.err.println("Failed to send hash chain signature to server.");
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
			return null;
		}
		
		return data;
	}
	
	/**
	 * Get the length of the hash chain. This is equal to the number of credits
	 * represented by the hash chain.
	 * 
	 * @return The length of the hash chain.
	 */
	public int getLength() {
		return hashChain.size();
	}
	
	/**
	 * Create a new hash chain of the desired length.
	 * 
	 * @param length The length of the hash chain to generate.
	 * @return A hash chain of the specified length.
	 */
	private Stack<CryptoCredit> generateHashChain(final int length) {
		final Stack<CryptoCredit> hashchain = new Stack<CryptoCredit>();
		
		final MessageDigest mdb;
		try {
			mdb = MessageDigest.getInstance(HASH_ALGORITHM);
		} catch (final Exception e) {
			System.err.println("Unable to create hash chain.");
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
			return null;
		}
		
		/* Use a random number to "seed" the hash chain. */
		final SecureRandom random = new SecureRandom();
		final byte[] hashChainSeed = new byte[HASHCHAIN_SEED_BYTES];
		random.nextBytes(hashChainSeed);
		byte[] nextValueToHash = hashChainSeed;
		
		/*
		 * Generate new hash chain values by repeating hashing the previous
		 * value.
		 */
		while (hashchain.size() < length) {
			final CryptoCredit nextCredit = new CryptoCredit();
			nextCredit.hash = mdb.digest(nextValueToHash);
			nextValueToHash = nextCredit.hash;
			hashchain.push(nextCredit);
		}
		
		if (DEBUG_GENERAL)
			System.out.println("Generated a hash chain of length " + length + " with top hash of \"" + Utility.getHexValue(nextValueToHash) + "\".");
		
		return hashchain;
	}
	
	/**
	 * Generates a tuple of the form (username, credits, top hash of hash
	 * chain). The {@link Bank} will later sign this tuple to verify to the
	 * {@link Server} that the {@link CryptoCreditHashChain} is valid.
	 * 
	 * @param username The username of the user that generated the hash chain.
	 * @param credits The number of credits represented by the hash chain.
	 * @param topOfChain The {@link CryptoCredit} at the top of the hash chain.
	 * @return A byte array that can be used to identify the hash chain to the
	 *         {@link Bank}.
	 */
	private static byte[] generateIdentifyingTuple(final String username, final int credits, final byte[] topOfChain) {
		final ByteArrayOutputStream byteArrayOutput = new ByteArrayOutputStream();
		final BufferedOutputStream bufferedOutput = new BufferedOutputStream(byteArrayOutput);
		final DataOutputStream dataOutput = new DataOutputStream(bufferedOutput);
		byte[] identifyingTuple = null;
		
		try {
			/* Username length. */
			dataOutput.writeInt(username.length());
			
			/* Username. */
			dataOutput.write(username.getBytes());
			
			/* Credits */
			dataOutput.writeInt(credits);
			
			/* Length of top of hash chain. */
			dataOutput.writeInt(topOfChain.length);
			
			/* Top of hash chain. */
			dataOutput.write(topOfChain);
			
			dataOutput.flush();
			bufferedOutput.flush();
			byteArrayOutput.flush();
			identifyingTuple = byteArrayOutput.toByteArray();
			
			/* Clean up. */
			dataOutput.close();
			bufferedOutput.close();
			byteArrayOutput.close();
		} catch (final Exception e) {
			System.err.println("Error generating identifying tuple for hash chain.");
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
		}
		
		return identifyingTuple;
	}
	
	/**
	 * Parse identifier and return the user ID.
	 * 
	 * @param data The identifier data.
	 * @return The user ID stored within the identifier.
	 */
	public static String getUserFromIdentifier(final byte[] data) {
		final ByteArrayInputStream byteArrayInput = new ByteArrayInputStream(data);
		final BufferedInputStream bufferedInput = new BufferedInputStream(byteArrayInput);
		final DataInputStream dataInput = new DataInputStream(bufferedInput);
		String result = null;
		
		try {
			/* Username length. */
			final int userNameLength = dataInput.readInt();
			
			/* Username. */
			final byte[] userName = new byte[userNameLength];
			dataInput.read(userName);
			result = new String(userName);
			
			/* Clean up. */
			dataInput.close();
			bufferedInput.close();
			byteArrayInput.close();
		} catch (final Exception e) {
			System.err.println("Error parsing username from hash chain identifier.");
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
		}
		
		return result;
	}
	
	/**
	 * Parse identifier and return the number of credits contained in the hash
	 * chain.
	 * 
	 * @param data The identifier data.
	 * @return The number of credits contained with the hash chain.
	 */
	public static Integer getCreditsFromIdentifier(final byte[] data) {
		final ByteArrayInputStream byteArrayInput = new ByteArrayInputStream(data);
		final BufferedInputStream bufferedInput = new BufferedInputStream(byteArrayInput);
		final DataInputStream dataInput = new DataInputStream(bufferedInput);
		Integer result = null;
		
		try {
			/* Username length. */
			final int userNameLength = dataInput.readInt();
			
			/* Username. */
			final byte[] userName = new byte[userNameLength];
			dataInput.read(userName);
			
			/* Credits. */
			result = new Integer(dataInput.readInt());
			
			/* Clean up. */
			dataInput.close();
			bufferedInput.close();
			byteArrayInput.close();
		} catch (final Exception e) {
			System.err.println("Error parsing credits from hash chain identifier.");
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
		}
		
		return result;
	}
	
	/**
	 * Parse identifier and return the {@link CryptoCredit} hash from the top of
	 * the hash chain.
	 * 
	 * @param data The identifier data.
	 * @return The {@link CryptoCredit} hash from the top of the hash chain.
	 */
	public static byte[] getTopHashFromIdentifier(final byte[] data) {
		final ByteArrayInputStream byteArrayInput = new ByteArrayInputStream(data);
		final BufferedInputStream bufferedInput = new BufferedInputStream(byteArrayInput);
		final DataInputStream dataInput = new DataInputStream(bufferedInput);
		byte[] result = null;
		
		try {
			/* Username length. */
			final int userNameLength = dataInput.readInt();
			
			/* Username. */
			final byte[] userName = new byte[userNameLength];
			dataInput.read(userName);
			
			/* Credits. */
			dataInput.readInt();
			
			/* Length of top of hash chain. */
			final int topOfChainLength = dataInput.readInt();
			
			/* Top of hash chain. */
			final byte[] topOfChain = new byte[topOfChainLength];
			dataInput.read(topOfChain);
			result = topOfChain;
			
			/* Clean up. */
			dataInput.close();
			bufferedInput.close();
			byteArrayInput.close();
		} catch (final Exception e) {
			System.err.println("Error parsing top of hash chain from hash chain identifier.");
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
		}
		
		return result;
	}
	
	/**
	 * Requests that the {@link Bank} signs a {@link CryptoCreditHashChain}
	 * identifier. If the {@link Bank} refuses to sign the identifier then this
	 * function will return null.
	 * 
	 * @param bankComms The {@link Comms} class to communicate with the
	 *        {@link Bank}.
	 * @param identifier The identifying tuple for the hash chain, that is sent
	 *        to the bank to be signed. Assumed to be encoded in base-64.
	 * @return The signature provided by the {@link Bank} for the hash chain, or
	 *         null if the bank refuses to sign the hash chain.
	 * @see Base64
	 */
	private static byte[] getBankSignature(final Comms bankComms, final byte[] identifier) {
		/* Request the signature from the bank. */
		bankComms.sendPacket(DecryptedPacket.CMD_SIGNHASHCHAIN, Base64.encodeBase64(identifier));
		
		while (true)
			try {
				final DecryptedPacket pckt = bankComms.recvPacket();
				
				if (pckt == null)
					/*
					 * Something has probably gone wrong, let's get out of here!
					 */
					return null;
				
				switch (pckt.command) {
/* @formatter:off */
					/***********************************************************
					 * Sign hash chain command
					 **********************************************************/
/* @formatter:on */
					case DecryptedPacket.CMD_SIGNHASHCHAIN:
						if (pckt.data.length == 0)
							return null;
						else
							return pckt.data;
						
/* @formatter:off*/
					/***********************************************************
					 * Other
					 **********************************************************/
/* @formatter:on */
					default:
						System.err.println("Unrecognised or unexpected command received from bank.");
				}
			} catch (final Exception e) {
				if (DEBUG_ERROR_TRACE)
					e.printStackTrace();
			}
	}
	
	/**
	 * Get the next <code>credits</code> number of {@link CryptoCredit}s from
	 * the hash chain, removing them from the hash chain. The number of credits
	 * retrieved from the hash chain will be equal to (or less than) the
	 * <code>credits</code> parameter. If the size of the hash chain is less
	 * than <code>credits</code>, then the complete hash chain will be returned.
	 * 
	 * @param credits The number of {@link CryptoCredit}s to retrieve.
	 * @return A stack of size <code>credits</code> (or possibly less), with the
	 *         top element of the stack being the credit to be spent.
	 */
	public Stack<byte[]> getNextCredits(final int credits) {
		final Stack<byte[]> result = new Stack<byte[]>();
		
		while (!hashChain.isEmpty() && result.size() < credits)
			result.push(hashChain.pop().hash);
		
		return result;
	}
	
	/**
	 * A utility function validate a {@link CryptoCredit} by checking that
	 * hashing the <code>suppliedHash</code> <code>credits</code> times gives
	 * the <code>lastHash</code>. This occurs at the {@link Bank} after the
	 * {@link Server} calls <code>processPayment</code>.
	 * 
	 * @param hash The {@link CryptoCredit} hash corresponding to the payment.
	 * @param credits The number of credits that the <code>suppliedHash</code>
	 *        is claimed to be worth.
	 * @param lastHash The last {@link CryptoCredit} that was processed.
	 * @return True if the {@link CryptoCredit} passes verification, otherwise
	 *         false.
	 */
	public static boolean validatePayment(final byte[] hash, final int credits, final byte[] lastHash) {
		if (hash == null || lastHash == null)
			return false;
		
		final MessageDigest mdb;
		try {
			mdb = MessageDigest.getInstance(HASH_ALGORITHM);
		} catch (final Exception e) {
			System.err.println("Unable to verify CryptoCredit hash.");
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
			return false;
		}
		
		/* Apply the hash function 'credits' times. */
		byte[] hashedHash = new byte[hash.length];
		System.arraycopy(hash, 0, hashedHash, 0, hash.length);
		for (int i = 0; i < credits; i++)
			hashedHash = mdb.digest(hashedHash);
		
		if (Arrays.equals(lastHash, hashedHash)) {
			if (DEBUG_GENERAL)
				System.out.println("Validation of CryptoCredit passed. \"" + Utility.getHexValue(hash) + "\" => \"" + Utility.getHexValue(lastHash) + "\".");
			return true;
		} else {
			if (DEBUG_GENERAL)
				System.err.println("Validation of CryptoCredit failed. \"" + Utility.getHexValue(hash) + "\" => \"" + Utility.getHexValue(hashedHash) + "\". Expected \"" + Utility.getHexValue(lastHash) + "\".");
			return false;
		}
	}
	
	/**
	 * A utility function to validate the supplied {@link CryptoCredit} hash by
	 * requesting that the {@link Bank} call the <code>validatePayment</code>
	 * function. A {@link CryptoCredit} is validated by checking with the
	 * {@link Bank} that the {@link CryptoCredit} hasn't been spent before.
	 * 
	 * @param bankComms The {@link Comms} class with which to communicate with
	 *        the {@link Bank}.
	 * @param userID The ID of user whose account should be credited.
	 * @param credits The number of credits declared by the {@link Client}.
	 * @param hash The hash of the {@link CryptoCredit} supplied by the
	 *        {@link Client}.
	 * @return True if the credits were added to the user's account, otherwise
	 *         false.
	 */
	public static synchronized boolean processPayment(final Comms bankComms, final String userID, final int credits, final byte[] hash) {
		if (credits > 0) {
			/* Request that the bank validates the CrytoCredit. */
			final String msg = userID + ";" + Integer.toString(credits) + ";" + Base64.encodeBase64String(hash);
			bankComms.sendPacket(DecryptedPacket.CMD_DEPOSITPAYMENT, msg);
			
			/* Wait for the bank's response. */
			while (true)
				try {
					final DecryptedPacket pckt = bankComms.recvPacket();
					
					if (pckt == null)
						/*
						 * Something has probably gone wrong, let's get out of
						 * here!
						 */
						return false;
					
					switch (pckt.command) {
/* @formatter:off */
						/*******************************************************
						 * Verify Credit command
						 ******************************************************/
/* @formatter:on */
						case DecryptedPacket.CMD_DEPOSITPAYMENT: {
							final String data = new String(pckt.data);
							final boolean result = Boolean.parseBoolean(data);
							
							if (result && DEBUG_GENERAL)
								System.out.println("Bank validated payment of CryptoCredit \"" + Utility.getHexValue(hash) + "\".");
							
							return result;
						}
						
						/*******************************************************
						 * Other command
						 ******************************************************/
						default:
							System.err.println("Unrecognised or unexpected command.");
					}
				} catch (final Exception e) {
					System.err.println("Error reading packet. Discarding...");
					if (DEBUG_ERROR_TRACE)
						e.printStackTrace();
				}
		}
		
		return false;
	}
	
	/**
	 * A utility function to validate the identifer of a new
	 * {@link CryptoCreditHashChain}. Checks the signature of the
	 * {@link CryptoCreditHashChain} to ensure that the {@link Bank} signed the
	 * {@link CryptoCreditHashChain}. If the signature verification passes, then
	 * the user's last {@link CryptoCredit} hash is updated to be the head of
	 * the new {@link CryptoCreditHashChain}.
	 * 
	 * @param bankVerification An {@link AsymmetricVerification} class to verify
	 *        that the {@link CryptoCreditHashChain} was signed by the
	 *        {@link Bank}.
	 * @param packetData The packet data containing the identifier and the
	 *        signature.
	 * @return True if the {@link CryptoCreditHashChain} is verified
	 *         successfully.
	 */
	public static synchronized boolean verifyHashChain(final AsymmetricVerification bankVerification, final byte[] packetData) {
		ByteArrayInputStream input = new ByteArrayInputStream(packetData);
		BufferedInputStream bufferedInput = new BufferedInputStream(input);
		DataInputStream dataInput = new DataInputStream(bufferedInput);
		byte[] identifier = null;
		byte[] signature = null;
		
		try {
			final int identifierSize = dataInput.readInt();
			identifier = new byte[identifierSize];
			dataInput.read(identifier);
			
			final int signatureSize = dataInput.readInt();
			signature = new byte[signatureSize];
			dataInput.read(signature);
			
			dataInput.close();
			bufferedInput.close();
			input.close();
		} catch (final Exception e) {
			System.err.println("Failed to parse hash chain.");
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
			return false;
		}
		
		/* Extract fields from identifier. */
		String userID = null;
		int credits = -1;
		byte[] topHash = null;
		input = new ByteArrayInputStream(identifier);
		bufferedInput = new BufferedInputStream(input);
		dataInput = new DataInputStream(bufferedInput);
		
		try {
			/* Username length. */
			final int userNameLength = dataInput.readInt();
			
			/* Username. */
			final byte[] userName = new byte[userNameLength];
			dataInput.read(userName);
			userID = new String(userName);
			
			/* Credits. */
			credits = dataInput.readInt();
			
			/* Length of top of hash chain. */
			final int topOfChainLength = dataInput.readInt();
			
			/* Top of hash chain. */
			final byte[] topOfChain = new byte[topOfChainLength];
			dataInput.read(topOfChain);
			topHash = topOfChain;
			
			/* Clean up. */
			dataInput.close();
			bufferedInput.close();
			input.close();
		} catch (final Exception e) {
			System.err.println("Error parsing top of hash chain from hash chain identifier.");
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
			return false;
		}
		
		if (DEBUG_GENERAL)
			System.out.println("Processing a hash chain for user \"" + userID + "\" for " + credits + " credits with top hash \"" + Utility.getHexValue(topHash) + "\".");
		
		/* Check that the bank signed the identifier. */
		try {
			if (!bankVerification.verify(identifier, signature)) {
				System.err.println("Hash chain failed verification.");
				return false;
			}
		} catch (final Exception e) {
			System.err.println("Failed to verify hashchain.");
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
			return false;
		}
		if (DEBUG_GENERAL)
			System.out.println("Hash chain passed verification.");
		return true;
		
		/* Update the user's account info. */
		//final UserData userInfo = getUser(userID);
		//if (DEBUG_PAYMENTS)
		//	System.out.println("Setting last hash for user \"" + userID + "\" to \"" + Utility.getHexValue(topHash) + "\"");
		//userInfo.lastHash = topHash;
	}
}

/******************************************************************************
 * END OF FILE: CryptoCreditHashChain.java
 *****************************************************************************/
