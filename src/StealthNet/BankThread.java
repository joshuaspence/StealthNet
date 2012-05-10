/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet
 * FILENAME:        BankThread.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     Implementation of StealthNet Bank for ELEC5616 programming
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
import java.security.NoSuchProviderException;
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
 * <p> A new instance is created for each peer such that multiple peers can be
 * active concurrently. This class handles {@link DecryptedPacket} and deals
 * with them accordingly.
 * 
 * <p> Peers use the {@link Bank} to sign {@link CryptoCreditHashChain}s, as
 * well as to retrieve their account balance. Peers can also use the
 * {@link Bank} to verify {@link CryptoCredit} payments. In the process, the
 * {@link Bank} is notified of {@link CryptoCredit}s that the {@link Client} has
 * used to make a purchase. In this way, the {@link Bank} is able to ensure that
 * no {@link CryptoCredit} is double spent.
 * 
 * @author Joshua Spence
 * 
 * @see Bank
 * @see Thread
 * @see CryptoCreditHashChain
 */
public class BankThread extends Thread {
	/* Debug options. */
	private static final boolean DEBUG_GENERAL = Debug.isDebug("StealthNet.BankThread.General");
	private static final boolean DEBUG_ERROR_TRACE = Debug.isDebug("StealthNet.BankThread.ErrorTrace") || Debug.isDebug("ErrorTrace");
	private static final boolean DEBUG_COMMANDS_NULL = Debug.isDebug("StealthNet.BankThread.Commands.Null");
	private static final boolean DEBUG_COMMANDS_PAYMENT = Debug.isDebug("StealthNet.BankThread.Commands.Payment");
	private static final boolean DEBUG_COMMANDS_SIGNHASHCHAIN = Debug.isDebug("StealthNet.BankThread.Commands.SignHashChain");
	private static final boolean DEBUG_COMMANDS_GETBALANCE = Debug.isDebug("StealthNet.BankThread.Commands.GetBalance");
	private static final boolean DEBUG_COMMANDS_DEPOSITPAYMENT = Debug.isDebug("StealthNet.BankThread.Commands.DepositPayment");
	private static final boolean DEBUG_ASYMMETRIC_ENCRYPTION = Debug.isDebug("StealthNet.BankThread.AsymmetricEncryption");
	private static final boolean DEBUG_BALANCES = Debug.isDebug("StealthNet.BankThread.Balances");
	
	/** The initial account balance for a new user logging into the bank. */
	private static final int INITIAL_BALANCE = 1000;
	
	/**
	 * Used to store details of the clients available funds. Note that "user"
	 * here can also represent a {@link Server}.
	 */
	private class UserData {
		BankThread userThread = null;
		int accountBalance = INITIAL_BALANCE;
		
		/**
		 * The last {@link CryptoCredit} hash used by a user to make a payment.
		 * All future payments must hash properly to this value.
		 * 
		 * <p> When a user generates a new {@link CryptoCreditHashChain}, this
		 * value is set to the {@link CryptoCredit} hash from the top of the
		 * {@link CryptoCreditHashChain}. Note that this hash cannot be spent.
		 */
		byte[] lastHash = null;
	}
	
	/** A list of users, indexed by their ID. */
	private static final Hashtable<String, UserData> userList = new Hashtable<String, UserData>();
	
	/**
	 * The user ID for the user owning the thread. {@link Server}s also "log in"
	 * to the bank, but use the username <code>server#{PUBLIC_KEY}</code> to do
	 * so.
	 */
	private String userID = null;
	
	/**
	 * A {@link Comms} class to handle communications for this peer (
	 * {@link Client} or {@link Server}).
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
	
	/**
	 * A {@link AsymmetricVerification} class to allow the bank to sign
	 * messages.
	 */
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
		
		/* Set up asymmetric verification. */
		AsymmetricVerification av = null;
		try {
			av = new SHA1withRSAAsymmetricVerification(bankKeys, bankKeys.getPublic());
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
	 * @throws NoSuchProviderException
	 */
	public BankThread(final Socket socket) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
		/* Thread constructor. */
		super("StealthNet.BankThread");
		
		if (DEBUG_GENERAL)
			System.out.println("Creating a BankThread.");
		
		/*
		 * Create a new Comms instance and accept sessions. Note that the
		 * client/server already has our public key and can hence encrypt
		 * messages destined for us. They will send us their public key (in an
		 * encrypted form) so that we can communicate securely.
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
	 * StealthNet. If the new user has not logged into the {@link Bank}
	 * previously, then a new bank account will be created for them (with an
	 * initial default balance).
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
	 * Remove a user from the user list. The user's account will not be deleted,
	 * such that their balance can be retrieved if they login again at a later
	 * period.
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
	 * Credit the user's account.
	 * 
	 * @param userID The user whose account should be credited.
	 * @param credits The number of credits to transfer between the accounts.
	 * @return True if the credits were added to the user's account, otherwise
	 *         false.
	 */
	private static synchronized boolean addCredits(final String userID, final int credits) {
		final UserData user = getUser(userID);
		boolean result = false;
		
		if (credits > 0) {
			user.accountBalance += credits;
			if (DEBUG_GENERAL)
				System.out.println("Added " + credits + " credits to user \"" + userID + "\" account.");
			user.userThread.stealthComms.sendPacket(DecryptedPacket.CMD_GETBALANCE, Integer.toString(user.accountBalance));
			result = true;
		}
		
		if (DEBUG_BALANCES)
			System.out.println(getUserBalances());
		
		return result;
	}
	
	/**
	 * Deduct credits from the user's account.
	 * 
	 * @param userID The ID of the user whose account should be deducted.
	 * @param credits The number of credits to deduct from the user's account.
	 * @return True if the credits were deducted from the user's account,
	 *         otherwise false.
	 */
	private static synchronized boolean deductCredits(final String userID, final int credits) {
		final UserData user = getUser(userID);
		boolean result = false;
		
		if (credits > 0 && user.accountBalance >= credits) {
			user.accountBalance -= credits;
			if (DEBUG_GENERAL)
				System.out.println("Deducted " + credits + " credits from user \"" + userID + "\" account.");
			user.userThread.stealthComms.sendPacket(DecryptedPacket.CMD_GETBALANCE, Integer.toString(user.accountBalance));
			result = true;
		}
		
		if (DEBUG_BALANCES)
			System.out.println(getUserBalances());
		
		return result;
	}
	
	/**
	 * Signs a {@link CryptoCreditHashChain} for a user. The hash chain will
	 * only be signed if the user has sufficient credit in their account and if
	 * the user is requesting credits from their <em>own</em> account.
	 * 
	 * <p> Once the {@link CryptoCreditHashChain} is signed, the signed credits
	 * are deducted from the user's account.
	 * 
	 * <p> The {@link Bank} maintains the last used hash for each peer in order
	 * to verify payments.
	 * 
	 * @param identifier The identifier for the {@link CryptoCreditHashChain} to
	 *        be signed. The identifier takes the form
	 *        <code>user;credits;topHash</code>.
	 */
	private synchronized void signHashChain(final byte[] identifier) {
		/* Extract fields from identifier. */
		final String userID = CryptoCreditHashChain.getUserFromIdentifier(identifier);
		final UserData user = getUser(userID);
		final int credits = CryptoCreditHashChain.getCreditsFromIdentifier(identifier).intValue();
		final byte[] topHash = CryptoCreditHashChain.getTopHashFromIdentifier(identifier);
		byte[] signature = new byte[0];
		
		if (DEBUG_COMMANDS_SIGNHASHCHAIN)
			System.out.println("Processing a CryptoCreditHashChain for user \"" + userID + "\" for " + credits + " credits with top hash \"" + Utility.getHexValue(topHash) + "\".");
		
		/* Make sure the user is requesting credits from their own account. */
		if (!userID.equals(this.userID))
			System.err.println("User \"" + this.userID + "\" cannot requested a signed hash chain for user \"" + userID + "\".");
		else /* Update the user's account info and sign the hash chain. */
		if (deductCredits(userID, credits)) {
			/* The user's account has been deducted. Sign the hash chain. */
			try {
				signature = asymmetricVerificationProvider.sign(identifier);
				
				if (DEBUG_COMMANDS_SIGNHASHCHAIN)
					System.out.println("Signed CryptoCreditHashChain \"" + Utility.getHexValue(topHash) + "\" with signature \"" + Utility.getHexValue(signature) + "\".");
				else
					System.out.println("Signed CryptoCreditHashChain \"" + Utility.getHexValue(topHash) + "\".");
			} catch (final Exception e) {
				if (DEBUG_COMMANDS_SIGNHASHCHAIN)
					System.err.println("Failed to sign CryptoCreditHashChain \"" + Utility.getHexValue(topHash) + "\".");
				else
					System.err.println("Failed to sign CryptoCreditHashChain.");
				if (DEBUG_ERROR_TRACE)
					e.printStackTrace();
			}
			
			/* Update the last hash for the user. */
			user.lastHash = topHash;
		} else if (DEBUG_COMMANDS_SIGNHASHCHAIN)
			System.err.println("Insufficient credit in user \"" + userID + "\" account.");
		
		/*
		 * Send the user the signature. Note that the signature will be empty if
		 * the bank refused to sign the hash chain.
		 */
		stealthComms.sendPacket(DecryptedPacket.CMD_SIGNHASHCHAIN, signature);
	}
	
	/**
	 * Validate a {@link CryptoCredit} payment and add the credits to our own
	 * account. This is used by a peer when receiving a {@link CryptoCredit}
	 * hash for payment. We can be sure that the user owning the
	 * {@link CryptoCredit} requested the payment because only the peer that
	 * generated the {@link CryptoCreditHashChain} will be able to generate
	 * valid {@link CryptoCredit} hashes for that {@link CryptoCreditHashChain}.
	 * 
	 * <p> If the validation is successful, then the credits are deposited into
	 * the current user's account.
	 * 
	 * @param userID The ID of the user that sent the {@link CryptoCredit}
	 *        payment.
	 * @param credits The number of credits that the user claimed to have sent.
	 * @param hash The {@link CryptoCredit} hash of the payment.
	 * @return True if the payment verified successfully, otherwise false.
	 */
	private synchronized boolean depositPayment(final String userID, final int credits, final byte[] hash) {
		boolean result = false;
		final UserData sendUser = getUser(userID);
		
		/*
		 * Check that apply the hash function 'credit' times to "hash" gives
		 * "lastHash".
		 */
		if (CryptoCreditHashChain.validatePayment(hash, credits, sendUser.lastHash)) {
			if (DEBUG_COMMANDS_DEPOSITPAYMENT)
				System.out.println("Depositing CryptoCredit \"" + hash + "\" into user \"" + this.userID + "\" account for " + credits + " credits.");
			result = true;
		} else if (DEBUG_COMMANDS_DEPOSITPAYMENT)
			System.err.println("CryptoCredit validation failed. Cannot deposit CryptoCredit \"" + Utility.getHexValue(hash) + "\" into user \"" + this.userID + "\" account.");
		
		/* Send the user the result. */
		stealthComms.sendPacket(DecryptedPacket.CMD_DEPOSITPAYMENT, Boolean.toString(result));
		
		/*
		 * This code is here so that the CMD_DEPOSITPAYMENT is sent before the
		 * account balance.
		 */
		if (result) {
			sendUser.lastHash = hash;
			addCredits(this.userID, credits);
		}
		return result;
	}
	
	/**
	 * Get a {@link String} containing all users and their current account
	 * balances. For debug purposes only.
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
		
		/* Strip the trailing newline character. */
		result = result.substring(0, result.length() - 1);
		return result;
	}
	
	/**
	 * The main function for the class. This function handles all type of
	 * StealthNet packets.
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
				
				/* Perform the relevant action based on the packet command. */
				switch (pckt.command) {
/* @formatter:off */
					/***********************************************************
					 * NULL command
					 **********************************************************/
/* @formatter:on */
					case DecryptedPacket.CMD_NULL: {
						if (DEBUG_COMMANDS_NULL)
							if (userID != null)
								System.out.println("User \"" + userID + "\" sent NULL command.");
							else
								System.out.println("Received NULL command.");
						break;
					}
					
					/***********************************************************
					 * Login command
					 **********************************************************/
					case DecryptedPacket.CMD_LOGIN: {
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
						break;
					}
					
					/***********************************************************
					 * Logout command
					 **********************************************************/
					case DecryptedPacket.CMD_LOGOUT: {
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
						if (userID == null) {
							System.err.println("Must be logged in to request account balance.");
							break;
						}
						
						if (DEBUG_COMMANDS_GETBALANCE)
							System.out.println("User \"" + userID + "\" requested account balance.");
						
						/* Send the user their account balance. */
						stealthComms.sendPacket(DecryptedPacket.CMD_GETBALANCE, Integer.toString(getUser(userID).accountBalance));
						break;
					}
					
					/***********************************************************
					 * Sign Hashchain command
					 **********************************************************/
					case DecryptedPacket.CMD_SIGNHASHCHAIN: {
						if (userID == null) {
							System.err.println("Must to logged in to request signed hash chain.");
							break;
						}
						
						if (DEBUG_COMMANDS_SIGNHASHCHAIN)
							System.out.println("User \"" + userID + "\" sent sign hash chain command.");
						signHashChain(Base64.decodeBase64(pckt.data));
						break;
					}
					
					/***********************************************************
					 * Validate Payment Command
					 **********************************************************/
					case DecryptedPacket.CMD_DEPOSITPAYMENT: {
						if (userID == null) {
							System.err.println("Must to logged in to accept payment.");
							break;
						}
						
						if (DEBUG_COMMANDS_DEPOSITPAYMENT)
							System.out.println("User \"" + userID + "\" sent validate payment command.");
						
						final String data = new String(pckt.data);
						final String user = data.split(";")[0];
						final int credits = Integer.parseInt(data.split(";")[1]);
						final byte[] hash = Base64.decodeBase64(data.split(";")[2]);
						depositPayment(user, credits, hash);
						break;
					}
					
					/*******************************************************
					 * Payment command
					 ******************************************************/
					case DecryptedPacket.CMD_PAYMENT:
						if (userID == null) {
							System.err.println("Unknown user sent payment command.");
							break;
						} else if (DEBUG_COMMANDS_GETBALANCE)
							System.out.println("User \"" + userID + "\" sent payment command.");
						
						final String data = new String(pckt.data);
						final int creditsSent = Integer.parseInt(data.split(";")[0]);
						final byte[] cryptoCreditHash = Base64.decodeBase64(data.split(";")[1].getBytes());
						
						if (DEBUG_COMMANDS_PAYMENT)
							System.out.println("User sent payment of " + creditsSent + " credits with CryptoCredit \"" + cryptoCreditHash + "\".");
						
						if (cryptoCreditHash == null || cryptoCreditHash.length == 0)
							break;
						else
						/*
						 * Add the credits to the user's account once the
						 * payment is verified.
						 */
						if (depositPayment(userID, creditsSent, cryptoCreditHash))
							addCredits(userID, creditsSent);
						break;
					
					/***********************************************************
					 * Other command
					 **********************************************************/
					default:
						System.err.println("Unrecognised or unexpected command.");
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
