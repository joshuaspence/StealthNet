/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Stephen Gould, Matt Barrie and Ryan Junee
 *
 * PACKAGE:         StealthNet
 * FILENAME:        ServerThread.java
 * AUTHORS:         Stephen Gould, Matt Barrie, Ryan Junee and Joshua Spence
 * DESCRIPTION:     Implementation of StealthNet Server for ELEC5616
 *                  programming assignment.
 *
 *****************************************************************************/

package StealthNet;

/* Import Libraries **********************************************************/

import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;

import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

import StealthNet.Security.AsymmetricEncryption;
import StealthNet.Security.RSAAsymmetricEncryption;

/* StealthNet.ServerThread Class Definition **********************************/

/**
 * Represents a thread within the operating system for communications between
 * the StealthNet server and a client.
 * 
 * A new instance is created for each client such that multiple clients can be
 * active concurrently. This class handles packets and deals with them
 * accordingly.
 * 
 * @author Stephen Gould
 * @author Matt Barrie
 * @author Ryan Junee
 * @author Joshua Spence
 */
public class ServerThread extends Thread {
	/** Debug options. */
	private static final boolean DEBUG_GENERAL               = Debug.isDebug("StealthNet.ServerThread.General");
	private static final boolean DEBUG_ERROR_TRACE           = Debug.isDebug("StealthNet.ServerThread.ErrorTrace") || Debug.isDebug("ErrorTrace");
	private static final boolean DEBUG_COMMANDS_NULL         = Debug.isDebug("StealthNet.ServerThread.Commands.Null");
	private static final boolean DEBUG_COMMANDS_LOGIN        = Debug.isDebug("StealthNet.ServerThread.Commands.Login");
	private static final boolean DEBUG_COMMANDS_MSG          = Debug.isDebug("StealthNet.ServerThread.Commands.Msg");
	private static final boolean DEBUG_COMMANDS_CHAT         = Debug.isDebug("StealthNet.ServerThread.Commands.Chat");
	private static final boolean DEBUG_COMMANDS_FTP          = Debug.isDebug("StealthNet.ServerThread.Commands.FTP");
	private static final boolean DEBUG_COMMANDS_CREATESECRET = Debug.isDebug("StealthNet.ServerThread.Commands.CreateSecret");
	private static final boolean DEBUG_COMMANDS_GETSECRET    = Debug.isDebug("StealthNet.ServerThread.Commands.GetSecret");
	private static final boolean DEBUG_ASYMMETRIC_ENCRYPTION = Debug.isDebug("StealthNet.ServerThread.AsymmetricEncryption");

	/**
	 * Used to store details of other clients that this thread may want to
	 * communicate with.
	 */
	private class UserData {
		ServerThread userThread = null;
		PublicKey publicKey = null;
	}

	/** Used to store client secret data. */
	private class SecretData {
		String name = null;
		String description = null;
		int cost = 0;
		String owner = null; /** Server knows, but clients should not. */
		String dirname = null;
		String filename = null;
	}

	/** A list of users, indexed by their ID. */
	private static final Hashtable<String, UserData> userList = new Hashtable<String, UserData>();

	/** A list of secret data, indexed by the SecretData.name field. */
	private static final Hashtable<String, SecretData> secretList = new Hashtable<String, SecretData>();

	/** The user ID for the user owning the thread. */
	private String userID = null;

	/** Public-private keypair options. */
	private static KeyPair serverKeys = null;
	private static final String PUBLIC_KEY_FILE = "keys/server/public.key";
	private static final String PRIVATE_KEY_FILE = "keys/server/private.key";
	private static final String PRIVATE_KEY_FILE_PASSWORD = "server";

	/** Initialise the server public-private keys. */
	static {
		/**
		 * Try to read keys from the JAR file first. If that doesn't work, then
		 * try to read keys from the file system. If that doesn't work, then
		 * create new keys.
		 */
		try {
			serverKeys = Utility.getPublicPrivateKeys(PUBLIC_KEY_FILE, PRIVATE_KEY_FILE, PRIVATE_KEY_FILE_PASSWORD);
		} catch (final Exception e) {
			System.err.println("Unable to retrieve/generate public/private keys.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			System.exit(1);
		}
		if (serverKeys == null) {
			System.err.println("Unable to retrieve/generate public-private keys.");
			System.exit(1);
		}

		/** Debug information. */
		if (DEBUG_ASYMMETRIC_ENCRYPTION) {
			final String publicKeyString = Utility.getHexValue(serverKeys.getPublic().getEncoded());
			final String privateKeyString = Utility.getHexValue(serverKeys.getPrivate().getEncoded());
			System.out.println("Public key: " + publicKeyString);
			System.out.println("Private key: " + privateKeyString);
		}
	}

	/** A StealthNetComms class to handle communications for this client. */
	private Comms clientComms = null;

	/** StealthNet bank options. */
	private final static String bankHostname = Comms.DEFAULT_BANKNAME;
	private final static int bankPort = Comms.DEFAULT_BANKPORT;
	private static Comms bankComms = null;
	private static final String BANK_PUBLIC_KEY_FILE = "keys/bank/public.key";

	/** Initialise the bank comms. */
	static {
		AsymmetricEncryption bankEncryption = null;
		try {
			bankEncryption = new RSAAsymmetricEncryption(serverKeys);
		} catch (final Exception e) {
			System.err.println(e.getMessage());
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			System.exit(1);
		}

		/**
		 * Set up asymmetric encryption. Get bank public key from JAR file.
		 */
		try {
			final PublicKey bankPublicKey = Utility.getPublicKey(BANK_PUBLIC_KEY_FILE);
			if (bankPublicKey == null) {
				System.err.println("Unable to determine bank public key.");
				System.exit(1);
			}

			bankEncryption.setPeerPublicKey(bankPublicKey);
		} catch (final Exception e) {
			System.err.println("Unable to set peer public key for bank connection.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			System.exit(1);
		}

		/** Initiate a connection with the StealthNet bank. */
		/** TODO: Probably want a timeout on this. */
		try {
			if (DEBUG_GENERAL) System.out.println("Initiating a connection with StealthNet bank '" + bankHostname + "' on port " + bankPort + ".");
			bankComms = new Comms(bankEncryption);
			bankComms.initiateSession(new Socket(bankHostname, bankPort));
		} catch (final Exception e) {
			System.err.println("Unable to connect to StealthNet bank.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			System.exit(1);
		}
	}

	/**
	 * Constructor.
	 * 
	 * @param socket The socket that the server is listening on.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public ServerThread(final Socket socket) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		/** Thread constructor. */
		super("StealthNet.ServerThread");

		if (DEBUG_GENERAL) System.out.println("Creating a ServerThread.");

		/**
		 * Create a new StealthNet.Comms instance and accept sessions. Note that
		 * the client already has our public key and can hence encrypt messages
		 * destined for us.
		 */
		clientComms = new Comms(new RSAAsymmetricEncryption(serverKeys), true);
		clientComms.acceptSession(socket);
	}

	/**
	 * Cleans up before destroying the class.
	 * 
	 * @throws IOException
	 */
	protected void finalize() throws IOException {
		if (clientComms != null)
			clientComms.terminateSession();
	}

	/**
	 * Add a user to the user list. Used to log the specified user into
	 * StealthNet.
	 * 
	 * @param id The ID of the user to add.
	 * @return True on success, false on failure or if the specified user
	 * already exists in the user list.
	 */
	private synchronized boolean addUser(final String id) {
		/** Make sure the specified user doesn't already exist in the user list. */
		UserData userInfo = userList.get(id);

		if (userInfo != null && userInfo.userThread != null)
			return false;
		else {
			/** Create new user data for the specified user. */
			userInfo = new UserData();
			userInfo.userThread = this;
			userInfo.publicKey = clientComms.getPeerPublicKey();
			userList.put(id, userInfo);

			if (DEBUG_GENERAL) System.out.println("Added user \"" + id + "\" to the user list.");
			return true;
		}
	}

	/**
	 * Add secret data to the secret list.
	 * 
	 * @param t The secret data to add.
	 * @return True on success, false on failure or if the secret data already
	 * exists in the secret list.
	 */
	private synchronized boolean addSecret(final SecretData t) {
		/** Make sure the secret doesn't already exist in the secret list. */
		final SecretData secretInfo = secretList.get(t.name);

		if (secretInfo != null)
			return false;
		else {
			/** Add the secret data to the secret list. */
			secretList.put(t.name, t);
			if (DEBUG_GENERAL) System.out.println("User '" + userID + "' added secret \"" + t.name + "\" to the secret list.");
			return true;
		}
	}

	/**
	 * Remove a user from the user list.
	 * 
	 * @param id The ID of the user to remove.
	 * @return True on success, false on failure or if the specified user
	 * doesn't exist in the user list.
	 */
	private synchronized boolean removeUser(final String id) {
		final UserData userInfo = userList.get(id);
		if (userInfo != null) {
			userInfo.userThread = null;
			if (DEBUG_GENERAL) System.out.println("Removed user \"" + id + "\" from the user list.");
			return true;
		} else
			return false;
	}

	/**
	 * Remove secret data from the secret list.
	 * 
	 * @param name The name of the secret data to remove.
	 * @return True on success, false on failure.
	 */
	@SuppressWarnings("unused")
	private synchronized boolean removeSecret(final String name) {
		secretList.remove(name);
		if (DEBUG_GENERAL) System.out.println("User '" + userID + "' removed secret \"" + name + "\" from the secret list.");
		return true;
	}

	/**
	 * Convert the user list to a String. Used to distribute the user list in a
	 * packet.
	 * 
	 * @return A String representing the user list. The output string is of the
	 * form "user;loggedOn\n..."
	 */
	private synchronized String userListAsString() {
		String userTable = "";
		final Enumeration<String> i = userList.keys();

		while (i.hasMoreElements()) {
			final String userKey = i.nextElement();
			final UserData userInfo = userList.get(userKey);

			userTable += userKey;
			userTable += ";";
			if (userInfo != null && userInfo.userThread != null)
				userTable += "true";
			else
				userTable += "false";
			userTable += "\n";
		}

		return userTable;
	}

	/**
	 * Convert the secret list to a String. Used to distribute the secret list
	 * in a packet.
	 * 
	 * @return A String representing the secret list. The output string is of
	 * the form "secretKey;cost;description;filename\n..."
	 */
	private synchronized String secretListAsString() {
		String secretTable = "";
		final Enumeration<String> i = secretList.keys();

		while (i.hasMoreElements()) {
			final String secretKey = i.nextElement();
			final SecretData secretInfo = secretList.get(secretKey);

			secretTable += secretKey;
			secretTable += ";";
			if (secretInfo != null) {
				secretTable += secretInfo.cost + ";";
				secretTable += secretInfo.description + ";";
				secretTable += secretInfo.filename;
			}
			secretTable += "\n";
		}

		return secretTable;
	}

	/**
	 * Send the user list (as a String) to all current users. Sent to all logged
	 * in users (including the new user) whenever a new user logs on.
	 */
	private synchronized void sendUserList() {
		final Enumeration<String> i = userList.keys();
		final String userTable = userListAsString();

		while (i.hasMoreElements()) {
			final String userKey = i.nextElement();
			final UserData userInfo = userList.get(userKey);

			if (userInfo != null && userInfo.userThread != null)
				if (userInfo.userThread.clientComms == null)
					userInfo.userThread = null;
				else {
					/** Send this user the user list in a packet. */
					if (DEBUG_GENERAL) System.out.println("Sending the user list to user \"" + userKey + "\".");
					userInfo.userThread.clientComms.sendPacket(DecryptedPacket.CMD_LIST, userTable);
				}
		}
	}

	/**
	 * Send the secret list (as a String) to all current users. Sent to all
	 * logged in users (including the new user) whenever a new user logs on.
	 */
	private synchronized void sendSecretList() {
		final Enumeration<String> i = userList.keys();
		final String secretTable = secretListAsString();

		while (i.hasMoreElements()) {
			final String userKey = i.nextElement();
			final UserData userInfo = userList.get(userKey);

			if (userInfo != null && userInfo.userThread != null)
				if (userInfo.userThread.clientComms == null)
					userInfo.userThread = null;
				else {
					/** Send this user the secret list in a packet. */
					if (DEBUG_GENERAL) System.out.println("Sending the secret list to user \"" + userKey + "\".");
					userInfo.userThread.clientComms.sendPacket(DecryptedPacket.CMD_SECRETLIST, secretTable);
				}
		}
	}

	/**
	 * The main function for the class. This function handles all type of
	 * StealthNet packets.
	 * 
	 * If the packet contains the login command, then we attempt to log the user
	 * into StealthNet. If successful, then we send all users a list of users
	 * and secrets.
	 * 
	 * If the packet contains the logout command, then the user is logged out of
	 * StealthNet, and this thread is terminated.
	 * 
	 * If the packet contains the message command, then the chat message
	 * contained in the packet data is sent to the destined user.
	 * 
	 * If the packet contains the chat command, then a chat session is started
	 * between the specified users.
	 * 
	 * If the packet contains the FTP command, then a file transfer session is
	 * started between the specified users.
	 * 
	 * If the packet contains the create secret command, then we create secret
	 * data from the StealthNet.Packet data, and retransmit the list of secrets
	 * to all currently logged in users.
	 */
	public void run() {
		if (DEBUG_GENERAL) System.out.println("Running ServerThread... (Thread ID is " + getId() + ")");

		DecryptedPacket pckt = new DecryptedPacket();
		try {
			while (pckt.command != DecryptedPacket.CMD_LOGOUT) {
				/** Receive a StealthNet.Packet. */
				pckt = clientComms.recvPacket();

				if (pckt == null)
					break;

				if (DEBUG_GENERAL) System.out.println("Received packet: (" + pckt.getDecodedString() + ").");

				/** Perform the relevant action based on the packet command. */
				switch (pckt.command) {
				/***********************************************************
				 * NULL command
				 **********************************************************/
				case DecryptedPacket.CMD_NULL:
				{
					if (DEBUG_COMMANDS_NULL)
						if (userID == null)
							System.out.println("Received NULL command.");
						else
							System.out.println("User '" + userID + "' sent NULL command.");
					break;
				}

				/***********************************************************
				 * Login command
				 **********************************************************/
				case DecryptedPacket.CMD_LOGIN:
				{
					if (DEBUG_COMMANDS_LOGIN) System.out.println("Received login command.");

					if (userID != null) {
						/** A user is already logged in. */
						System.err.println("User \"" + userID + "\" trying to log in twice.");
						break;
					}

					/** Extract the user ID from the packet data. */
					userID = new String(pckt.data);

					/** Log the user in. */
					if (!addUser(userID)) {
						System.out.println("User \"" + userID + "\" is already logged in.");

						/** Cancel the current login attempt. */
						pckt.command = DecryptedPacket.CMD_LOGOUT;
						userID = null;
					} else {
						System.out.println("User \"" + userID + "\" has logged in.");

						if (DEBUG_COMMANDS_LOGIN) {
							System.out.println("Distributing user list...");
							System.out.println("Distributing user list: \"" + userListAsString().replace('\n', ';') + "\"");
						}
						sendUserList();

						if (DEBUG_COMMANDS_LOGIN) {
							System.out.println("Distributing secret list...");
							System.out.println("Distributing secret list: \"" + secretListAsString().replace('\n', ';') + "\"");
						}
						sendSecretList();
					}
					break;
				}

				/***********************************************************
				 * Logout command
				 **********************************************************/
				case DecryptedPacket.CMD_LOGOUT:
				{
					if (userID == null)
						System.err.println("Unknown user trying to log out.");
					else
						System.out.println("User \"" + userID + "\" has logged out.");

					/** The code will now break out of the while loop. */
					break;
				}

				/***********************************************************
				 * Message command
				 **********************************************************/
				case DecryptedPacket.CMD_MSG:
				{
					if (userID == null) {
						System.err.println("Unknown user trying to send message.");
						break;
					} else
						if (DEBUG_COMMANDS_MSG) System.out.println("User '" + userID + "' sent message command.");

					/** Send the message to all users. */
					final String msg = "[" + userID + "] " + new String(pckt.data);
					final Enumeration<String> i = userList.keys();
					while (i.hasMoreElements()) {
						final String userKey = i.nextElement();
						final UserData userInfo = userList.get(userKey);

						if (userInfo != null && userInfo.userThread != null) {
							if (DEBUG_COMMANDS_MSG) System.out.println("Sending message \"" + msg + "\" to user \"" + userKey + "\".");
							userInfo.userThread.clientComms.sendPacket(DecryptedPacket.CMD_MSG, msg);
						}
					}
					break;
				}

				/***********************************************************
				 * Chat command
				 **********************************************************/
				case DecryptedPacket.CMD_CHAT:
				{
					if (userID == null) {
						System.err.println("Unknown user trying to chat.");
						break;
					} else
						if (DEBUG_COMMANDS_CHAT) System.out.println("User '" + userID + "' sent chat command.");

					/**
					 * NOTE: Data will be of the form "user@host:port".
					 */
					final String data = new String(pckt.data);
					final String iAddr = data.split("@")[1];
					final String userKey = data.split("@")[0];
					final UserData userInfo = userList.get(userKey);

					if (userInfo == null || userInfo.userThread == null) {
						final byte msg_type = DecryptedPacket.CMD_MSG;
						final String msg = "[*SVR*] User not logged in";

						if (DEBUG_COMMANDS_CHAT) System.out.println("Returning error message \"" + msg + "\" to user '" + userID + "'.");
						clientComms.sendPacket(msg_type, msg);
					} else if (userInfo.userThread == Thread.currentThread()) {
						final byte msg_type = DecryptedPacket.CMD_MSG;
						final String msg = "[*SVR*] Cannot chat to self";

						if (DEBUG_COMMANDS_CHAT) System.out.println("Returning error message \"" + msg + "\" to user '" + userID + "'.");
						clientComms.sendPacket(msg_type, msg);
					} else {
						final byte msg_type = DecryptedPacket.CMD_CHAT;
						final String msg = userID + "@" + iAddr;

						if (DEBUG_COMMANDS_CHAT) System.out.println("Sending chat message \"" + msg + "\" to user \"" + userKey + "\".");
						userInfo.userThread.clientComms.sendPacket(msg_type, msg);
					}

					break;
				}

				/***********************************************************
				 * FTP command
				 **********************************************************/
				case DecryptedPacket.CMD_FTP:
				{
					if (userID == null) {
						System.err.println("Unknown user trying to transfer file.");
						break;
					} else
						if (DEBUG_COMMANDS_FTP) System.out.println("User '" + userID + "' sent FTP command.");

					/**
					 * NOTE: Data will be of the form "user@host:port".
					 */
					final String data = new String(pckt.data);
					final String iAddr = data.split("@")[1];
					final String userKey = data.split("@")[0];
					final UserData userInfo = userList.get(userKey);

					if (userInfo == null || userInfo.userThread == null) {
						final byte msg_type = DecryptedPacket.CMD_MSG;
						final String msg = "[*SVR*] User not logged in";

						if (DEBUG_COMMANDS_FTP) System.out.println("Returning error message \"" + msg + "\" to user '" + userID + "'.");
						clientComms.sendPacket(msg_type, msg);
					} else if (userInfo.userThread == Thread.currentThread()) {
						final byte msg_type = DecryptedPacket.CMD_MSG;
						final String msg = "[*SVR*] Cannot ftp to self";

						if (DEBUG_COMMANDS_FTP) System.out.println("Returning error message \"" + msg + "\" to user '" + userID + "'.");
						clientComms.sendPacket(msg_type, msg);
					} else {
						final byte msg_type = DecryptedPacket.CMD_FTP;
						final String msg = userID + "@" + iAddr;

						if (DEBUG_COMMANDS_FTP) System.out.println("Sending file transfer message \"" + msg + "\" to user \"" + userKey + "\".");
						userInfo.userThread.clientComms.sendPacket(msg_type, msg);
					}
					break;
				}

				/***********************************************************
				 * Create Secret command
				 **********************************************************/
				case DecryptedPacket.CMD_CREATESECRET:
				{
					if (userID == null) {
						System.err.println("Unknown user trying to create secret.");
						break;
					} else
						if (DEBUG_COMMANDS_CREATESECRET) System.out.println("User '" + userID + "' sent create secret command.");

					/** Depacketise the create secret command. */
					final SecretData t = new SecretData();
					t.owner = userID;
					t.name = "";
					t.description = "";
					t.cost = 0;
					t.dirname = "";
					t.filename = "";

					final StringTokenizer tokens = new StringTokenizer(new String(pckt.data), ";");
					t.name = tokens.nextToken();
					t.description = tokens.nextToken();
					t.cost = Integer.parseInt(tokens.nextToken());
					t.dirname = tokens.nextToken();
					t.filename = tokens.nextToken();

					addSecret(t);
					if (DEBUG_COMMANDS_CREATESECRET)
						System.out.println("User '" + userID + "' added secret \"" + t.name + "\" to secret list.");
					else
						System.out.println("User '" + userID + "' added secret.\n");

					if (DEBUG_COMMANDS_CREATESECRET)
						System.out.println("Distributing secret list: \"" + secretListAsString() + "\"");
					else
						System.out.println("Distributing secret list.\n");
					sendSecretList();
					break;
				}
				/***********************************************************
				 * Get Secret command
				 **********************************************************/
				case DecryptedPacket.CMD_GETSECRET:
				{
					if (userID == null) {
						System.err.println("Unknown user trying to get secret.");
						break;
					} else
						if (DEBUG_COMMANDS_GETSECRET) System.out.println("User '" + userID + "' sent Get Secret command.");

					/**
					 * NOTE: Data will be of the form "name@address".
					 */
					final String data = new String(pckt.data);
					final String name = data.split("@")[0];
					final String destination = data.split("@")[1];
					final SecretData secretInfo = secretList.get(name);

					if (secretInfo == null) {
						final byte msg_type = DecryptedPacket.CMD_MSG;
						final String msg = "[*SVR*] Secret is not available";

						if (DEBUG_COMMANDS_GETSECRET) System.out.println("Returning error message \"" + msg + "\" to user '" + userID + "'.");
						clientComms.sendPacket(msg_type, msg);
					} else {
						final String user = secretInfo.owner;
						final UserData userInfo = userList.get(user);

						if (userInfo == null || userInfo.userThread == null) {
							final byte msg_type = DecryptedPacket.CMD_MSG;
							final String msg = "[*SVR*] Secret is not currently available";

							if (DEBUG_COMMANDS_GETSECRET) System.out.println("Returning error message \"" + msg + "\" to user '" + userID + "'.");
							clientComms.sendPacket(msg_type, msg);
						} else if (userInfo.userThread == Thread.currentThread()) {
							final byte msg_type = DecryptedPacket.CMD_MSG;
							final String msg = "[*SVR*] You can't purchase a secret from yourself!";

							if (DEBUG_COMMANDS_GETSECRET) System.out.println("Returning error message \"" + msg + "\" to user '" + userID + "'.");
							clientComms.sendPacket(msg_type, msg);
						} else {
							/** Wait for the signed purchase. */

							/** Get the bank to verify the signed purchase. */

							/** Send an acknowledgement. */

							final String fileName = secretInfo.dirname + secretInfo.filename;
							final byte msg_type = DecryptedPacket.CMD_GETSECRET;
							final String msg = fileName + "@" + destination;

							if (DEBUG_COMMANDS_GETSECRET) System.out.println("Sending get secret message \"" + msg + "\" to user \"" + user + "\".");
							userInfo.userThread.clientComms.sendPacket(msg_type, msg);
						}
					}
					break;
				}

				/***********************************************************
				 * Get Public Key command
				 **********************************************************/
				case DecryptedPacket.CMD_GETPUBLICKEY:
				{
					if (userID == null) {
						System.err.println("Unknown user trying to get public key.");
						break;
					} else
						if (DEBUG_COMMANDS_LOGIN) System.out.println("User '" + userID + "' sent get public key command.");

					/** Extract the user ID from the packet data. */
					final String requestedUserID = new String(pckt.data);
					if (DEBUG_COMMANDS_LOGIN) System.out.println("User '" + userID + "' is requesting the public key of user '" + requestedUserID + "'.");

					/** Get the public key of the requested user. */
					final PublicKey key = userList.get(requestedUserID).publicKey;

					/** Send the public key back to the client. */
					if (DEBUG_COMMANDS_LOGIN) System.out.println("Sending user '" + userID + "' the public key of user '" + requestedUserID + "'.");
					clientComms.sendPacket(DecryptedPacket.CMD_GETPUBLICKEY, Base64.encodeBase64String(key.getEncoded()));
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
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
		} catch (final Exception e) {
			System.err.println("Error running server thread.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
		}

		/**
		 * We only reach this code when a user is logging out, so lets remove
		 * the logged out user from the user list.
		 */
		if (userID != null)
			removeUser(userID);

		/**
		 * Now that a user has logged out, re-transmit the user list to all
		 * currently logged in users.
		 */
		if (DEBUG_GENERAL)
			System.out.println("Distributing user list: \"" + userListAsString() + "\"");
		else
			System.out.println("Distributing user list.\n");
		sendUserList();

		/** Clean up. */
		if (clientComms != null) {
			clientComms.terminateSession();
			clientComms = null;
		}
	}
}

/******************************************************************************
 * END OF FILE: ServerThread.java
 *****************************************************************************/