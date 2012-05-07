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
import java.util.Stack;

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
	/** Algorithm to use for the hashchain {@link MessageDigest}. */
	private static final String HASH_ALGORITHM = "MD5";
	
	/** The number of (random) bytes to use as a seed for the hash chain. */
	private static final int HASHCHAIN_SEED_BYTES = 8;
	
	/** Class to represent individual CryptoCredits. */
	private class CryptoCredit {
		byte[] hash = null;
	}
	
	/** Stack to store the hash chain. */
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
			return null;
		}
		
		new SecureRandom();
		final byte[] hashChainSeed = new byte[HASHCHAIN_SEED_BYTES];
		byte[] nextValueToHash = hashChainSeed;
		
		while (hashchain.size() < length) {
			final CryptoCredit nextCredit = new CryptoCredit();
			nextCredit.hash = mdb.digest(nextValueToHash);
			nextValueToHash = nextCredit.hash;
			
			hashchain.push(nextCredit);
		}
		
		return hashchain;
	}
	
	/**
	 * Generates a tuple of the form (username, credits, top hash of hash
	 * chain). The bank will later sign this tuple to verify to the server that
	 * the hash chain is valid.
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
		}
		
		return result;
	}
	
	/**
	 * Requests that the bank signs a hash chain identifier. If the bank refuses
	 * to sign the identifier then this function will return null.
	 * 
	 * @param bankComms The {@link Comms} class to communicate with the bank.
	 * @param identifier The identifying tuple for the hash chain, that is sent
	 *        to the bank to be signed.
	 * @return The signature provided by the {@link Bank} for the hash chain, or
	 *         null if the bank refuses to sign the hash chain.
	 */
	private static byte[] getBankSignature(final Comms bankComms, final byte[] identifier) {
		bankComms.sendPacket(DecryptedPacket.CMD_SIGNHASHCHAIN, identifier);
		DecryptedPacket pckt = new DecryptedPacket();
		
		while (true)
			try {
				pckt = bankComms.recvPacket();
				
				switch (pckt.command) {
/* @formatter:off */
					/***********************************************************
					 * Sign hash chain command
					 **********************************************************/
/* @formatter:on */
					case DecryptedPacket.CMD_SIGNHASHCHAIN:
						return pckt.data;
						
/* @formatter:off*/
					/***********************************************************
					 * Other
					 **********************************************************/
/* @formatter:on */
					default:
						System.err.println("Unrecognised or unexpected command received from bank.");
				}
			} catch (final Exception e) {}
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
		
		if (credits > 0)
			while (hashChain.size() > 0 && result.size() < credits)
				result.push(hashChain.pop().hash);
		
		return result;
	}
	
	/**
	 * Verifies a {@link CryptoCredit} by checking that hashing the
	 * <code>suppliedHash</code> <code>credits</code> times gives the
	 * <code>lastHash</code>.
	 * 
	 * @param hash The {@link CryptoCredit} hash corresponding to the payment.
	 * @param credits The number of credits that the <code>suppliedHash</code>
	 *        is claimed to be worth.
	 * @param lastHash The last {@link CryptoCredit} that was processed.
	 * @return True if the {@link CryptoCredit} passes verification, otherwise
	 *         false.
	 */
	public static boolean verify(final byte[] hash, final int credits, final byte[] lastHash) {
		return true;
		/* TODO: this doesn't seem to be working properly */
		/*
		 * final MessageDigest mdb; try { mdb =
		 * MessageDigest.getInstance(HASH_ALGORITHM); } catch (final Exception
		 * e) { System.err.println("Unable to verify CryptoCredit hash.");
		 * return false; }
		 */
		/* Apply the hash function 'credits' times. */
		/*
		 * for (int i = 1; i < credits; i++) hash = mdb.digest(hash);
		 * 
		 * if (Arrays.equals(lastHash, hash)) return true; else return false;
		 */
	}
}

/******************************************************************************
 * END OF FILE: CryptoCreditHashChain.java
 *****************************************************************************/
