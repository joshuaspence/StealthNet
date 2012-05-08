/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet
 * FILENAME:        BankThread.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     Implementation of StealthNet bank for ELEC5616 programming
 * 					assignment.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet;

/* Import Libraries ******************************************************** */

import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Enumeration;
import java.util.Hashtable;

import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

import StealthNet.CryptoCreditHashChain.CryptoCredit;
import StealthNet.Security.AsymmetricVerification;
import StealthNet.Security.RSAAsymmetricEncryption;
import StealthNet.Security.SHA1withRSAAsymmetricVerification;

/* StealthNet.BankThread Class Definition ********************************** */

/**
 * Represents a {@link Thread} within the operating system for communications
 * between the StealthNet {@link Bank} and a peer (either a {@link Client} or a
 * {@link Server}).
 * 
 * A new instance is created for each peer such that multiple peers can be
 * active concurrently. This class handles {@link DecryptedPacket} and deals
 * with them accordingly.
 * 
 * {@link Client}s use the {@link Bank} to sign {@link CryptoCredit} hash
 * chains. {@link Server}s use the bank to verify CryptoCredit payments.
 * 
 * @author Joshua Spence
 * 
 * @see Bank
 * @see Thread
 */
public class BankThread extends Thread {
	/* Debug options. */
	private static final boolean DEBUG_GENERAL = Debug.isDebug("StealthNet.BankThread.General");
	private static final boolean DEBUG_ERROR_TRACE = Debug.isDebug("StealthNet.BankThread.ErrorTrace") || Debug.isDebug("ErrorTrace");
	private static final boolean DEBUG_COMMANDS_NULL = Debug.isDebug("StealthNet.BankThread.Commands.Null");
	private static final boolean DEBUG_COMMANDS_LOGIN = Debug.isDebug("StealthNet.BankThread.Commands.Login");
	private static final boolean DEBUG_COMMANDS_LOGOUT = Debug.isDebug("StealthNet.BankThread.Commands.Logout");
	private static final boolean DEBUG_COMMANDS_GETBALANCE = Debug.isDebug("StealthNet.BankThread.Commands.GetBalance");
	private static final boolean DEBUG_COMMANDS_SIGNHASHCHAIN = Debug.isDebug("StealthNet.BankThread.Commands.SignHashChain");
	private static final boolean DEBUG_ASYMMETRIC_ENCRYPTION = Debug.isDebug("StealthNet.BankThread.AsymmetricEncryption");
	
	/** The initial account balance for a new user logging into the bank. */
	private static final int INITIAL_BALANCE = 1000;
	
	/** Used to store details of the clients available funds. */
	private class UserData {
		BankThread userThread = null;
		int accountBalance = INITIAL_BALANCE;
		byte[] lastHash = null;
	}
	
	/** A list of users, indexed by their ID. */
	private static final Hashtable<String, UserData> userList = new Hashtable<String, UserData>();
	
	/** The user ID for the user owning the thread. */
	private String userID = null;
	
	/**
	 * A {@link Comms} class to handle communications for this {@link Client} or
	 * {@link Server}.
	 */
	private Comms stealthComms = null;
	
	/** The location of the {@link Bank}'s {@link PublicKey} file. */
	private static final String PUBLIC_KEY_FILE = "keys/bank/public.key";
	
	/** The location of the {@link Bank}'s {@link PrivateKey} file. */
	private static final String PRIVATE_KEY_FILE = "keys/bank/private.key";
	
	/** The password to decrypt the server's {@link PrivateKey} file. */
	private static final String PRIVATE_KEY_FILE_PASSWORD = "bank";
	
	/** The public-private {@link KeyPair} for this bank. */
	private static final KeyPair bankKeys;
	
	/** To allow the bank to sign messages. */
	private static final AsymmetricVerification asymmetricVerificationProvider;
	
	/* Initialise the bank public-private key pair. */
	static {
		KeyPair kp = null;
		
		/*
		 * Try to read keys from the JAR file first. If that doesn't work, then
		 * try to read keys from the file system. If that doesn't work, then
		 * create new keys.
		 */
		try {
			kp = Utility.getPublicPrivateKeys(PUBLIC_KEY_FILE, PRIVATE_KEY_FILE, PRIVATE_KEY_FILE_PASSWORD);
		} catch (final Exception e) {
			System.err.println("Unable to retrieve/generate public-private keys.");
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
			System.exit(1);
		}
		if (kp == null) {
			System.err.println("Unable to retrieve/generate public-private keys.");
			System.exit(1);
		}
		bankKeys = kp;
		
		/* Debug information. */
		if (DEBUG_ASYMMETRIC_ENCRYPTION) {
			final String publicKeyString = Utility.getHexValue(bankKeys.getPublic().getEncoded());
			final String privateKeyString = Utility.getHexValue(bankKeys.getPrivate().getEncoded());
			System.out.println("Public key: " + publicKeyString);
			System.out.println("Private key: " + privateKeyString);
		}
		
		AsymmetricVerification av = null;
		try {
			av = new SHA1withRSAAsymmetricVerification(bankKeys);
			av.setPeerPublicKey(bankKeys.getPublic());
		} catch (final Exception e) {
			System.err.println("Unable to enable asymmetric verification.");
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
			System.exit(1);
		}
		asymmetricVerificationProvider = av;
	}
	
	/**
	 * Constructor.
	 * 
	 * @param socket The {@link Socket} on which the {@link Bank} has accepted a
	 *        connection.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public BankThread(final Socket socket) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		/* Thread constructor. */
		super("StealthNet.BankThread");
		
		if (DEBUG_GENERAL)
			System.out.println("Creating a BankThread.");
		
		/*
		 * Create a new Comms instance and accept sessions. Note that the
		 * client/server already has our public key and can hence encrypt
		 * messages destined for us.
		 */
		stealthComms = new Comms(new RSAAsymmetricEncryption(bankKeys), true);
		stealthComms.acceptSession(socket);
	}
	
	/**
	 * Cleans up before destroying the class.
	 * 
	 * @throws IOException
	 */
	@Override
	protected void finalize() throws IOException {
		if (stealthComms != null)
			stealthComms.terminateSession();
	}
	
	/**
	 * Add a user to the user list. Used to log the specified user into
	 * StealthNet.
	 * 
	 * @param id The ID of the user to add.
	 * @return True on success, false on failure or if the specified user
	 *         already exists in the user list.
	 */
	private synchronized boolean addUser(final String id) {
		/* Make sure the specified user doesn't already exist in the user list. */
		UserData userInfo = getUser(id);
		
		if (userInfo != null && userInfo.userThread != null)
			return false;
		else {
			/* Create new user data for the specified user. */
			userInfo = new UserData();
			userInfo.userThread = this;
			userList.put(id, userInfo);
			
			if (DEBUG_GENERAL)
				System.out.println("Added user \"" + id + "\" to the user list.");
			return true;
		}
	}
	
	/**
	 * Retrieve a user from the user list.
	 * 
	 * @param id The ID of the user to add.
	 * @return The {@link UserData} corresponding to the specified ID.
	 */
	private static synchronized UserData getUser(final String id) {
		return userList.get(id);
	}
	
	/**
	 * Retrieve all users from the user list.
	 * 
	 * @return The user list.
	 */
	private static synchronized Hashtable<String, UserData> getUsers() {
		return userList;
	}
	
	/**
	 * Remove a user from the user list.
	 * 
	 * @param id The ID of the user to remove.
	 * @return True on success, false on failure or if the specified user
	 *         doesn't exist in the user list.
	 */
	private static synchronized boolean removeUser(final String id) {
		final UserData userInfo = getUser(id);
		if (userInfo != null) {
			userInfo.userThread = null;
			if (DEBUG_GENERAL)
				System.out.println("Removed user \"" + id + "\" from the user list.");
			return true;
		} else
			return false;
	}
	
	/**
	 * Credit the user's account. Also sends the user their updated account
	 * balance.
	 * 
	 * @param userID The user whose account should be credited.
	 * @param credits The number of credits to transfer between the accounts.
	 * @return True if the credits were added to the user's account, otherwise
	 *         false.
	 */
	@SuppressWarnings("unused")
	private static synchronized boolean addCredits(final String userID, final int credits) {
		final UserData user = getUser(userID);
		boolean result = false;
		
		if (credits > 0) {
			user.accountBalance += credits;
			result = true;
		}
		
		/* Send the user their (possibly updated) account balance. */
		user.userThread.stealthComms.sendPacket(DecryptedPacket.CMD_GETBALANCE, Integer.toString(user.accountBalance));
		
		return result;
	}
	
	/**
	 * Transfer credits from one user's account to another user's account. Also
	 * sends both users their updated account balances.
	 * 
	 * @param fromUserID The ID of user whose account should be deducted.
	 * @param toUserID The ID of the user whose account should be credited.
	 * @param credits The number of credits to add to the user's account.
	 * @return True if the credits were added to the user's account, otherwise
	 *         false.
	 */
	@SuppressWarnings("unused")
	private static synchronized boolean transferCredits(final String fromUserID, final String toUserID, final int credits) {
		final UserData fromUser = getUser(fromUserID);
		final UserData toUser = getUser(toUserID);
		boolean result = false;
		
		if (credits > 0 && fromUser.accountBalance >= credits) {
			fromUser.accountBalance -= credits;
			toUser.accountBalance += credits;
			result = true;
		}
		
		/* Send the users their (possibly updated) account balances. */
		fromUser.userThread.stealthComms.sendPacket(DecryptedPacket.CMD_GETBALANCE, Integer.toString(fromUser.accountBalance));
		toUser.userThread.stealthComms.sendPacket(DecryptedPacket.CMD_GETBALANCE, Integer.toString(toUser.accountBalance));
		
		return result;
	}
	
	/**
	 * Deduct credits from the user's account. Also sends the user their updated
	 * account balance.
	 * 
	 * @param userID The ID of the user whose account should be deducted.
	 * @param credits The number of credits to deduct from the user's account.
	 * @return True if the credits were deducted from the user's account,
	 *         otherwise false.
	 */
	private static synchronized boolean deductCredits(final String userID, final int credits) {
		final UserData user = getUser(userID);
		boolean result = false;
		
		if (credits > 0) {
			user.accountBalance -= credits;
			result = true;
		}
		
		/* Send the user their (possibly updated) account balance. */
		user.userThread.stealthComms.sendPacket(DecryptedPacket.CMD_GETBALANCE, Integer.toString(user.accountBalance));
		
		return result;
	}
	
	/**
	 * Signs a {@link CryptoCreditHashChain} for a user. The hash chain will
	 * only be signed if the user has sufficient credit in their account and if
	 * the user is requesting credits from their <em>own</em> account.
	 */
	private synchronized void signHashChain(final byte[] identifier) {
		/* Extract fields from identifier. */
		final String userID = CryptoCreditHashChain.getUserFromIdentifier(identifier);
		final int credits = CryptoCreditHashChain.getCreditsFromIdentifier(identifier).intValue();
		final byte[] topHash = CryptoCreditHashChain.getTopHashFromIdentifier(identifier);
		byte[] signature = new byte[0];
		
		if (DEBUG_COMMANDS_SIGNHASHCHAIN)
			System.out.println("Processing a hash chain for user '" + userID + "' for " + credits + " credits with top hash \"" + Utility.getHexValue(topHash) + "\".");
		
		/* Make sure the user is requesting credits from their own account. */
		if (!userID.equals(this.userID)) {
			if (DEBUG_COMMANDS_SIGNHASHCHAIN)
				System.err.println("User '" + this.userID + "' requested a signed hash chain for user '" + userID + "'.");
		} else /* Update the user's account info and sign the hash chain. */
		if (deductCredits(userID, credits)) {
			/* The user's account has been deducted. Sign the hash chain. */
			try {
				signature = asymmetricVerificationProvider.sign(identifier);
				
				if (DEBUG_COMMANDS_SIGNHASHCHAIN)
					System.out.println("Signed hash chain with identifier \"" + Utility.getHexValue(identifier) + "\". Signature is \"" + Utility.getHexValue(signature) + "\".");
			} catch (final Exception e) {
				System.err.println("Failed to sign hash chain.");
				if (DEBUG_ERROR_TRACE)
					e.printStackTrace();
			}
			
			/* Update the last hash for the user. */
			getUser(userID).lastHash = topHash;
		} else if (DEBUG_COMMANDS_SIGNHASHCHAIN)
			System.out.println("Insufficient credit in user '" + userID + "' account.");
		
		/*
		 * Send the user the signature. Note that the signature will be empty if
		 * the bank refused to sign the hash chain.
		 */
		stealthComms.sendPacket(DecryptedPacket.CMD_SIGNHASHCHAIN, signature);
		
		/* Send the user their (possibly updated) account balance. */
		stealthComms.sendPacket(DecryptedPacket.CMD_GETBALANCE, Integer.toString(getUser(userID).accountBalance));
	}
	
	/**
	 * Verifies a payment. This is used by the {@link Server} when receiving a
	 * CryptoCredit hash for payment, to ensure that the CryptoCredit hasn't
	 * already been spent with another vendor. We can be sure that the user
	 * requested the payment because only the {@link Client} that generated the
	 * hash chain will be able to generate valid CryptoCredit hashes for that
	 * {@link CryptoCreditHashChain}.
	 * 
	 * @param userID
	 * @param credits
	 * @param hash
	 */
	private synchronized void verifyPayment(final String userID, final int credits, final byte[] hash) {
		boolean result = false;
		
		if (CryptoCreditHashChain.validate(hash, credits, getUser(userID).lastHash)) {
			getUser(userID).lastHash = hash;
			result = true;
		}
		
		/* Send the response. */
		stealthComms.sendPacket(DecryptedPacket.CMD_VERIFYCREDIT, Boolean.toString(result));
	}
	
	/**
	 * Get a {@link String} containing all users and their current account
	 * balances.
	 * 
	 * @return A {@link String} containing all users and their current account
	 *         balances.
	 */
	private static synchronized String getUserBalances() {
		String result = "";
		final Enumeration<String> i = getUsers().keys();
		
		while (i.hasMoreElements()) {
			final String userID = i.nextElement();
			final UserData userInfo = getUser(userID);
			
			result += userID + ":\t" + userInfo.accountBalance + "\t" + (userInfo.lastHash == null ? "(none)" : Utility.getHexValue(userInfo.lastHash)) + "\n";
		}
		
		result = result.substring(0, result.length() - 1);
		return result;
	}
	
	/**
	 * The main function for the class. This function handles all type of
	 * StealthNet packets. TODO
	 */
	@Override
	public void run() {
		if (DEBUG_GENERAL)
			System.out.println("Running BankThread... (Thread ID is " + getId() + ")");
		
		DecryptedPacket pckt = new DecryptedPacket();
		try {
			while (pckt.command != DecryptedPacket.CMD_LOGOUT) {
				/* Receive a StealthNet.Packet. */
				pckt = stealthComms.recvPacket();
				
				if (pckt == null)
					break;
				
				if (DEBUG_GENERAL)
					System.out.println("Received packet: (" + pckt.getDecodedString() + ").");
				
				/* Perform the relevant action based on the packet command. */
				switch (pckt.command) {
/* @formatter:off */
					/***********************************************************
					 * NULL command
					 **********************************************************/
/* @formatter:on */
					case DecryptedPacket.CMD_NULL: {
						if (DEBUG_COMMANDS_NULL)
							System.out.println("Received NULL command.");
						break;
					}
					
					/***********************************************************
					 * Login command
					 **********************************************************/
					case DecryptedPacket.CMD_LOGIN: {
						if (DEBUG_COMMANDS_LOGIN)
							System.out.println("Received login command.");
						
						if (userID != null) {
							/* A user is already logged in. */
							System.err.println("User \"" + userID + "\" trying to log in twice.");
							break;
						}
						
						/* Extract the user ID from the packet data. */
						userID = new String(pckt.data);
						
						/* Log the user in. */
						if (!addUser(userID)) {
							System.out.println("User \"" + userID + "\" is already logged in.");
							
							/* Cancel the current login attempt. */
							pckt.command = DecryptedPacket.CMD_LOGOUT;
							userID = null;
							break;
						}
						
						System.out.println("User \"" + userID + "\" has logged in.");
						
						/* Send the user their account balance. */
						stealthComms.sendPacket(DecryptedPacket.CMD_GETBALANCE, Integer.toString(getUser(userID).accountBalance));
						
						break;
					}
					
					/***********************************************************
					 * Logout command
					 **********************************************************/
					case DecryptedPacket.CMD_LOGOUT: {
						if (DEBUG_COMMANDS_LOGOUT)
							System.out.println("Received logout command.");
						
						if (userID == null)
							System.err.println("Unknown user trying to log out.");
						else
							System.out.println("User \"" + userID + "\" has logged out.");
						
						/* The code will now break out of the while loop. */
						break;
					}
					
					/***********************************************************
					 * Get Balance command
					 **********************************************************/
					case DecryptedPacket.CMD_GETBALANCE: {
						if (DEBUG_COMMANDS_GETBALANCE)
							System.out.println("Received get balance command.");
						
						/* Send the user their account balance. */
						stealthComms.sendPacket(DecryptedPacket.CMD_GETBALANCE, Integer.toString(getUser(userID).accountBalance));
						break;
					}
					
					/***********************************************************
					 * Sign Hashchain command
					 **********************************************************/
					case DecryptedPacket.CMD_SIGNHASHCHAIN: {
						signHashChain(Base64.decodeBase64(pckt.data));
						System.out.println(getUserBalances());
						break;
					}
					
					/***********************************************************
					 * Verify Credit command
					 **********************************************************/
					case DecryptedPacket.CMD_VERIFYCREDIT: {
						final String data = new String(pckt.data);
						final String user = data.split(";")[0];
						final int credits = Integer.parseInt(data.split(";")[1]);
						final byte[] hash = Base64.decodeBase64(data.split(";")[2]);
						verifyPayment(user, credits, hash);
						break;
					}
					
					/***********************************************************
					 * Unknown command
					 **********************************************************/
					default:
						System.err.println("Unrecognised command.");
				}
			}
		} catch (final IOException e) {
			System.err.println("User \"" + userID + "\" session terminated.");
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
		} catch (final Exception e) {
			System.err.println("Error running bank thread.");
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
		}
		
		/*
		 * We only reach this code when a user is logging out, so lets remove
		 * the logged out user from the user list.
		 */
		if (userID != null)
			removeUser(userID);
		
		/* Clean up. */
		if (stealthComms != null) {
			stealthComms.terminateSession();
			stealthComms = null;
		}
	}
}

/******************************************************************************
 * END OF FILE: BankThread.java
 *****************************************************************************/
