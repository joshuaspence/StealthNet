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
import java.util.Hashtable;

import javax.crypto.NoSuchPaddingException;

import StealthNet.Security.AsymmetricVerification;
import StealthNet.Security.RSAAsymmetricEncryption;
import StealthNet.Security.SHA1withRSAAsymmetricVerification;

/* StealthNet.BankThread Class Definition ********************************** */

/**
 * TODO
 * 
 * @author Joshua Spence
 */
public class BankThread extends Thread {
	/* Debug options. */
	private static final boolean DEBUG_GENERAL = Debug.isDebug("StealthNet.BankThread.General");
	private static final boolean DEBUG_ERROR_TRACE = Debug.isDebug("StealthNet.BankThread.ErrorTrace") || Debug.isDebug("ErrorTrace");
	private static final boolean DEBUG_COMMANDS_NULL = Debug.isDebug("StealthNet.BankThread.Commands.Null");
	private static final boolean DEBUG_COMMANDS_LOGIN = Debug.isDebug("StealthNet.BankThread.Commands.Login");
	private static final boolean DEBUG_COMMANDS_LOGOUT = Debug.isDebug("StealthNet.BankThread.Commands.Logout");
	private static final boolean DEBUG_ASYMMETRIC_ENCRYPTION = Debug.isDebug("StealthNet.BankThread.AsymmetricEncryption");
	
	/* Constants. */
	private static final int INITIAL_BALANCE = 100;
	
	/** Used to store details of the clients available funds. */
	private class UserBankAccount {
		BankThread userThread = null;
		int balance = INITIAL_BALANCE;
	}
	
	/** A list of users, indexed by their ID. */
	private static final Hashtable<String, UserBankAccount> userAccounts = new Hashtable<String, UserBankAccount>();
	
	/** The user ID for the user owning the thread. */
	private String userID = null;
	
	/**
	 * A {@link Comms} class to handle communications for this {@link Client} or
	 * {@link Server}.
	 */
	private Comms stealthComms = null;
	
	/** The location of the bank's {@link PublicKey} file. */
	private static final String PUBLIC_KEY_FILE = "keys/bank/public.key";
	
	/** The location of the bank's {@link PrivateKey} file. */
	private static final String PRIVATE_KEY_FILE = "keys/bank/private.key";
	
	/** The password to decrypt the server's {@link PrivateKey} file. */
	private static final String PRIVATE_KEY_FILE_PASSWORD = "bank";
	
	/** The public-private {@link KeyPair} for this bank. */
	private static final KeyPair bankKeys;
	
	/** To allow the bank to sign messages. */
	private static final AsymmetricVerification asymmetricVerificationProvider;
	
	/* Initialise the bank public-private {@link KeyPair}. */
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
	 * @param socket The {@link Socket} that the bank is listening on.
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
	 * Add a user to the user list. Used to log the specified user into the
	 * StealthNet bank.
	 * 
	 * @param id The ID of the user to add.
	 * @return True on success, false on failure or if the specified user
	 *         already exists in the user list.
	 */
	private synchronized boolean addUser(final String id) {
		/* Make sure the specified user doesn't already exist in the user list. */
		UserBankAccount userAccount = userAccounts.get(id);
		
		if (userAccount != null && userAccount.userThread != null)
			return false;
		else {
			/* Create new user data for the specified user. */
			userAccount = new UserBankAccount();
			userAccount.userThread = this;
			userAccounts.put(id, userAccount);
			
			if (DEBUG_GENERAL)
				System.out.println("Added user \"" + id + "\" to the user list.");
			return true;
		}
	}
	
	/**
	 * Remove a user from the user list.
	 * 
	 * @param id The ID of the user to remove.
	 * @return True on success, false on failure or if the specified user
	 *         doesn't exist in the user list.
	 */
	private synchronized boolean removeUser(final String id) {
		final UserBankAccount userAccount = userAccounts.get(id);
		if (userAccount != null) {
			userAccount.userThread = null;
			if (DEBUG_GENERAL)
				System.out.println("Removed user \"" + id + "\" from the user list.");
			return true;
		} else
			return false;
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
						} else
							System.out.println("User \"" + userID + "\" has logged in.");
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
			System.err.println("Error running server thread.");
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
