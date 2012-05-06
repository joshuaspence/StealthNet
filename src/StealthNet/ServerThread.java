/* @formatter:off */
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
import java.util.StringTokenizer;

import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

import StealthNet.Security.AsymmetricEncryption;
import StealthNet.Security.RSAAsymmetricEncryption;

/* StealthNet.ServerThread Class Definition ******************************** */

/**
 * Represents a {@link Thread} within the operating system for communications
 * between the StealthNet {@link Server} and a {@link Client}.
 * 
 * A new instance is created for each {@link Client} such that multiple
 * {@link Client} can be active concurrently. This class handles
 * {@link DecryptedPacket} and deals with them accordingly.
 * 
 * @author Stephen Gould
 * @author Matt Barrie
 * @author Ryan Junee
 * @author Joshua Spence
 * 
 * @see Server
 * @see Thread
 */
public class ServerThread extends Thread {
	/* Debug options. */
	private static final boolean DEBUG_GENERAL = Debug.isDebug("StealthNet.ServerThread.General");
	private static final boolean DEBUG_ERROR_TRACE = Debug.isDebug("StealthNet.ServerThread.ErrorTrace") || Debug.isDebug("ErrorTrace");
	private static final boolean DEBUG_COMMANDS_NULL = Debug.isDebug("StealthNet.ServerThread.Commands.Null");
	private static final boolean DEBUG_COMMANDS_LOGIN = Debug.isDebug("StealthNet.ServerThread.Commands.Login");
	private static final boolean DEBUG_COMMANDS_MSG = Debug.isDebug("StealthNet.ServerThread.Commands.Msg");
	private static final boolean DEBUG_COMMANDS_CHAT = Debug.isDebug("StealthNet.ServerThread.Commands.Chat");
	private static final boolean DEBUG_COMMANDS_FTP = Debug.isDebug("StealthNet.ServerThread.Commands.FTP");
	private static final boolean DEBUG_COMMANDS_CREATESECRET = Debug.isDebug("StealthNet.ServerThread.Commands.CreateSecret");
	private static final boolean DEBUG_COMMANDS_GETSECRET = Debug.isDebug("StealthNet.ServerThread.Commands.GetSecret");
	private static final boolean DEBUG_COMMANDS_GETPUBLICKEY = Debug.isDebug("StealthNet.ServerThread.Commands.GetPublicKey");
	private static final boolean DEBUG_ASYMMETRIC_ENCRYPTION = Debug.isDebug("StealthNet.ServerThread.AsymmetricEncryption");
	private static final boolean DEBUG_PAYMENTS = Debug.isDebug("StealthNet.ServerThread.Payments");
	
	/** Initial balance for a new user logging in to the {@link Server}. */
	private static final int INITIAL_BALANCE = 0;
	
	/**
	 * Used to store details of other clients that this thread may want to
	 * communicate with.
	 */
	private class UserData {
		String name = null;
		ServerThread userThread = null;
		PublicKey publicKey = null;
		int accountBalance = INITIAL_BALANCE;
		byte[] lastHash = null;
	}
	
	/** Used to store client secret data. */
	private class SecretData {
		String name = null;
		String description = null;
		int cost = 0;
		
		/** Server knows, but clients should not. */
		String owner = null;
		
		String dirname = null;
		String filename = null;
	}
	
	/** A list of users, indexed by their ID. */
	private static final Hashtable<String, UserData> userList = new Hashtable<String, UserData>();
	
	/** A list of secret data, indexed by the SecretData.name field. */
	private static final Hashtable<String, SecretData> secretList = new Hashtable<String, SecretData>();
	
	/** The user ID for the user owning this {@link Thread}. */
	private String userID = null;
	
	/** The public-private {@link KeyPair} for this server. */
	private static final KeyPair serverKeys;
	
	/** The location of the server's {@link PublicKey} file. */
	private static final String PUBLIC_KEY_FILE = "keys/server/public.key";
	
	/** The location of the server's {@link PrivateKey} file. */
	private static final String PRIVATE_KEY_FILE = "keys/server/private.key";
	
	/** The password to decrypt the server's {@link PrivateKey} file. */
	private static final String PRIVATE_KEY_FILE_PASSWORD = "server";
	
	/* Initialise the server public-private key pair */
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
		serverKeys = kp;
		
		/* Debug information. */
		if (DEBUG_ASYMMETRIC_ENCRYPTION) {
			final String publicKeyString = Utility.getHexValue(serverKeys.getPublic().getEncoded());
			final String privateKeyString = Utility.getHexValue(serverKeys.getPrivate().getEncoded());
			System.out.println("Public key: " + publicKeyString);
			System.out.println("Private key: " + privateKeyString);
		}
	}
	
	/** A {@link Comms} class to handle communications for this client. */
	private Comms clientComms = null;
	
	/** The hostname on which to connect to the StealthNet {@link Bank}. */
	private final static String bankHostname = Comms.DEFAULT_BANKNAME;
	
	/** The port number on which to connect to the StealthNet {@link Bank}. */
	private final static int bankPort = Comms.DEFAULT_BANKPORT;
	
	/**
	 * A {@link Comms} class to handle communications to the {@link Bank}. Note
	 * that we need only a single connection to the {@link Bank}, not a separate
	 * connection for each {@link Client} connection.
	 */
	private static Comms bankComms = null;
	
	/** The location of the {@link PublicKey} file of the {@link Bank}. */
	private static final String BANK_PUBLIC_KEY_FILE = "keys/bank/public.key";
	
	/* Initialise the bank communications. */
	static {
		AsymmetricEncryption bankEncryption = null;
		try {
			bankEncryption = new RSAAsymmetricEncryption(serverKeys);
		} catch (final Exception e) {
			System.err.println(e.getMessage());
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
			System.exit(1);
		}
		
		/* Set up asymmetric encryption. Get bank public key from JAR file. */
		try {
			final PublicKey bankPublicKey = Utility.getPublicKey(BANK_PUBLIC_KEY_FILE);
			if (bankPublicKey == null) {
				System.err.println("Unable to determine bank public key.");
				System.exit(1);
			}
			
			bankEncryption.setPeerPublicKey(bankPublicKey);
		} catch (final Exception e) {
			System.err.println("Unable to set peer public key for bank connection.");
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
			System.exit(1);
		}
		
		/* Initiate a connection with the StealthNet bank. */
		/* TODO: Probably want a timeout on this. */
		try {
			if (DEBUG_GENERAL)
				System.out.println("Initiating a connection with StealthNet bank '" + bankHostname + "' on port " + bankPort + ".");
			bankComms = new Comms(bankEncryption);
			bankComms.initiateSession(new Socket(bankHostname, bankPort));
		} catch (final Exception e) {
			System.err.println("Unable to connect to StealthNet bank.");
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
			System.exit(1);
		}
	}
	
	/**
	 * Constructor.
	 * 
	 * @param socket The {@link Socket} on which the {@link Server} has accepted
	 *        a connection.
	 * 
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public ServerThread(final Socket socket) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		/* Thread constructor. */
		super("StealthNet.ServerThread");
		
		if (DEBUG_GENERAL)
			System.out.println("Creating a ServerThread.");
		
		/*
		 * Create a new Comms instance and accept sessions. Note that the client
		 * already has our public key and can hence encrypt messages destined
		 * for us.
		 */
		clientComms = new Comms(new RSAAsymmetricEncryption(serverKeys), true);
		clientComms.acceptSession(socket);
	}
	
	/**
	 * Cleans up before destroying the class.
	 * 
	 * @throws IOException
	 */
	@Override
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
			userInfo.name = id;
			userInfo.userThread = this;
			userInfo.publicKey = clientComms.getPeerPublicKey();
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
	private synchronized UserData getUser(final String id) {
		return userList.get(id);
	}
	
	/**
	 * Retrieve all users from the user list.
	 * 
	 * @return The user list.
	 */
	private synchronized Hashtable<String, UserData> getUsers() {
		return userList;
	}
	
	/**
	 * Remove a user from the user list.
	 * 
	 * @param id The ID of the user to remove.
	 * @return True on success, false on failure or if the specified user
	 *         doesn't exist in the user list.
	 */
	private synchronized boolean removeUser(final String id) {
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
	 * Add {@link SecretData} to the secret list.
	 * 
	 * @param t The secret data to add.
	 * @return True on success, false on failure or if the secret data already
	 *         exists in the secret list.
	 */
	private synchronized boolean addSecret(final SecretData t) {
		/* Make sure the secret doesn't already exist in the secret list. */
		final SecretData secretInfo = getSecret(t.name);
		
		if (secretInfo != null)
			return false;
		else {
			/* Add the secret data to the secret list. */
			secretList.put(t.name, t);
			if (DEBUG_GENERAL)
				System.out.println("User '" + userID + "' added secret \"" + t.name + "\" to the secret list.");
			return true;
		}
	}
	
	/**
	 * Retrieve a secret from the secret list.
	 * 
	 * @param name The name of the secret to retrieve.
	 * @return The {@link SecretData} corresponding to the specified name.
	 */
	private synchronized SecretData getSecret(final String name) {
		return secretList.get(name);
	}
	
	/**
	 * Retrieve the secret list.
	 * 
	 * @return The secret list.
	 */
	private synchronized Hashtable<String, SecretData> getSecrets() {
		return secretList;
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
		if (DEBUG_GENERAL)
			System.out.println("User '" + userID + "' removed secret \"" + name + "\" from the secret list.");
		return true;
	}
	
	/**
	 * Convert the user list to a {@link String}. Used to distribute the user
	 * list to all users in a {@link DecryptedPacket}.
	 * 
	 * @return A {@link String} representing the user list. The output string is
	 *         of the form "user;loggedOn\n..."
	 */
	private synchronized String userListAsString() {
		String userTable = "";
		final Enumeration<String> i = getUsers().keys();
		
		while (i.hasMoreElements()) {
			final String userKey = i.nextElement();
			final UserData userInfo = getUser(userKey);
			
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
	 * Convert the secret list to a {@link String}. Used to distribute the
	 * secret list to all users in a {link DecryptedPacket}.
	 * 
	 * @return A {@link String} representing the secret list. The output string
	 *         is of the form "secretKey;cost;description;filename\n..."
	 */
	private synchronized String secretListAsString() {
		String secretTable = "";
		final Enumeration<String> i = getSecrets().keys();
		
		while (i.hasMoreElements()) {
			final String secretKey = i.nextElement();
			final SecretData secretInfo = getSecret(secretKey);
			
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
	 * Send the user list (as a {@link String}) to all users. Sent to all
	 * logged-in users (including the new user) whenever a new user logs on or
	 * whenever a user logs off.
	 */
	private synchronized void sendUserList() {
		final Enumeration<String> i = getUsers().keys();
		final String userTable = userListAsString();
		
		while (i.hasMoreElements()) {
			final String userKey = i.nextElement();
			final UserData userInfo = getUser(userKey);
			
			if (userInfo != null && userInfo.userThread != null)
				if (userInfo.userThread.clientComms == null)
					userInfo.userThread = null;
				else {
					/* Send this user the user list in a packet. */
					if (DEBUG_GENERAL)
						System.out.println("Sending the user list to user \"" + userKey + "\".");
					userInfo.userThread.clientComms.sendPacket(DecryptedPacket.CMD_LIST, userTable);
				}
		}
	}
	
	/**
	 * Send the secret list (as a {@link String}) to all users. Sent to all
	 * logged in users (including the new user) whenever a secret is added or
	 * removed from the secret list.
	 */
	private synchronized void sendSecretList() {
		final Enumeration<String> i = getUsers().keys();
		final String secretTable = secretListAsString();
		
		while (i.hasMoreElements()) {
			final String userKey = i.nextElement();
			final UserData userInfo = getUser(userKey);
			
			if (userInfo != null && userInfo.userThread != null)
				if (userInfo.userThread.clientComms == null)
					userInfo.userThread = null;
				else {
					/* Send this user the secret list in a packet. */
					if (DEBUG_GENERAL)
						System.out.println("Sending the secret list to user \"" + userKey + "\".");
					userInfo.userThread.clientComms.sendPacket(DecryptedPacket.CMD_SECRETLIST, secretTable);
				}
		}
	}
	
	/**
	 * The main function for the class. This function handles all type of
	 * {@link DecryptedPacket}s.
	 * 
	 * If the packet contains the <code>CMD_LOGIN</code> command, then we
	 * attempt to log the user into StealthNet. If successful, then we send all
	 * users an updated list of users and secrets.
	 * 
	 * If the packet contains the <code>CMD_LOGOUT</code> command, then the user
	 * is logged out of StealthNet, and this thread is terminated.
	 * 
	 * If the packet contains the <code>CMD_MSG</code> command, then the chat
	 * message contained in the packet data is sent to the destined user.
	 * 
	 * If the packet contains the <code>CMD_CHAT</code> command, then a chat
	 * session is started between the specified users.
	 * 
	 * If the packet contains the <code>CMD_FTP</code> command, then a file
	 * transfer session is started between the specified users.
	 * 
	 * If the packet contains the <code>CMD_CREATESECRET</code> command, then we
	 * create secret data from the packet data, and retransmit the list of
	 * secrets to all currently logged in users.
	 * 
	 * If the packet contains the <code>CMD_GETSECRET</code> command, then we
	 * deduct the necessary credit from the user's account, and then establish
	 * the transfer of the secret file.
	 * 
	 * If the packet contains the <code>CMD_GETPUBLICKEY</code> command, then we
	 * send the user the encoded {@link PublicKey} of the requested user.
	 */
	@Override
	public void run() {
		if (DEBUG_GENERAL)
			System.out.println("Running ServerThread... (Thread ID is " + getId() + ")");
		
		DecryptedPacket pckt = new DecryptedPacket();
		try {
			while (pckt.command != DecryptedPacket.CMD_LOGOUT) {
				/** Receive a StealthNet.Packet. */
				pckt = clientComms.recvPacket();
				
				if (pckt == null)
					break;
				
				if (DEBUG_GENERAL)
					System.out.println("Received packet: (" + pckt.getDecodedString() + ").");
				
				/** Perform the relevant action based on the packet command. */
				switch (pckt.command) {
/* @formatter:off */
					/***********************************************************
					 * NULL command
					 **********************************************************/
/* @formatter:on */
					case DecryptedPacket.CMD_NULL: {
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
					case DecryptedPacket.CMD_LOGOUT: {
						if (userID == null)
							System.err.println("Unknown user trying to log out.");
						else
							System.out.println("User \"" + userID + "\" has logged out.");
						
						/* The code will now break out of the while loop. */
						break;
					}
					
					/***********************************************************
					 * Message command
					 **********************************************************/
					case DecryptedPacket.CMD_MSG: {
						if (userID == null) {
							System.err.println("Unknown user trying to send message.");
							break;
						} else if (DEBUG_COMMANDS_MSG)
							System.out.println("User '" + userID + "' sent message command.");
						
						/* Send the message to all users. */
						final String msg = "[" + userID + "] " + new String(pckt.data);
						final Hashtable<String, UserData> users = getUsers();
						final Enumeration<String> i = users.keys();
						while (i.hasMoreElements()) {
							final String userKey = i.nextElement();
							final UserData userInfo = users.get(userKey);
							
							if (userInfo != null && userInfo.userThread != null) {
								if (DEBUG_COMMANDS_MSG)
									System.out.println("Sending message \"" + msg + "\" to user \"" + userKey + "\".");
								userInfo.userThread.clientComms.sendPacket(DecryptedPacket.CMD_MSG, msg);
							}
						}
						break;
					}
					
					/***********************************************************
					 * Chat command
					 **********************************************************/
					case DecryptedPacket.CMD_CHAT: {
						if (userID == null) {
							System.err.println("Unknown user trying to chat.");
							break;
						} else if (DEBUG_COMMANDS_CHAT)
							System.out.println("User '" + userID + "' sent chat command.");
						
						/*
						 * NOTE: Data will be of the form "user@host:port".
						 */
						final String data = new String(pckt.data);
						final String iAddr = data.split("@")[1];
						final String userKey = data.split("@")[0];
						final UserData userInfo = getUser(userKey);
						
						if (userInfo == null || userInfo.userThread == null) {
							final byte msg_type = DecryptedPacket.CMD_MSG;
							final String msg = "[*SVR*] User not logged in";
							
							if (DEBUG_COMMANDS_CHAT)
								System.out.println("Returning error message \"" + msg + "\" to user '" + userID + "'.");
							clientComms.sendPacket(msg_type, msg);
						} else if (userInfo.userThread == Thread.currentThread()) {
							final byte msg_type = DecryptedPacket.CMD_MSG;
							final String msg = "[*SVR*] Cannot chat to self";
							
							if (DEBUG_COMMANDS_CHAT)
								System.out.println("Returning error message \"" + msg + "\" to user '" + userID + "'.");
							clientComms.sendPacket(msg_type, msg);
						} else {
							final byte msg_type = DecryptedPacket.CMD_CHAT;
							final String msg = userID + "@" + iAddr;
							
							if (DEBUG_COMMANDS_CHAT)
								System.out.println("Sending chat message \"" + msg + "\" to user \"" + userKey + "\".");
							userInfo.userThread.clientComms.sendPacket(msg_type, msg);
						}
						
						break;
					}
					
					/***********************************************************
					 * FTP command
					 **********************************************************/
					case DecryptedPacket.CMD_FTP: {
						if (userID == null) {
							System.err.println("Unknown user trying to transfer file.");
							break;
						} else if (DEBUG_COMMANDS_FTP)
							System.out.println("User '" + userID + "' sent FTP command.");
						
						/*
						 * NOTE: Data will be of the form "user@host:port".
						 */
						final String data = new String(pckt.data);
						final String iAddr = data.split("@")[1];
						final String userKey = data.split("@")[0];
						final UserData userInfo = getUser(userKey);
						
						if (userInfo == null || userInfo.userThread == null) {
							final byte msg_type = DecryptedPacket.CMD_MSG;
							final String msg = "[*SVR*] User not logged in";
							
							if (DEBUG_COMMANDS_FTP)
								System.out.println("Returning error message \"" + msg + "\" to user '" + userID + "'.");
							clientComms.sendPacket(msg_type, msg);
						} else if (userInfo.userThread == Thread.currentThread()) {
							final byte msg_type = DecryptedPacket.CMD_MSG;
							final String msg = "[*SVR*] Cannot ftp to self";
							
							if (DEBUG_COMMANDS_FTP)
								System.out.println("Returning error message \"" + msg + "\" to user '" + userID + "'.");
							clientComms.sendPacket(msg_type, msg);
						} else {
							final byte msg_type = DecryptedPacket.CMD_FTP;
							final String msg = userID + "@" + iAddr;
							
							if (DEBUG_COMMANDS_FTP)
								System.out.println("Sending file transfer message \"" + msg + "\" to user \"" + userKey + "\".");
							userInfo.userThread.clientComms.sendPacket(msg_type, msg);
						}
						break;
					}
					
					/***********************************************************
					 * Create Secret command
					 **********************************************************/
					case DecryptedPacket.CMD_CREATESECRET: {
						if (userID == null) {
							System.err.println("Unknown user trying to create secret.");
							break;
						} else if (DEBUG_COMMANDS_CREATESECRET)
							System.out.println("User '" + userID + "' sent create secret command.");
						
						/* Depacketise the create secret command. */
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
					case DecryptedPacket.CMD_GETSECRET: {
						if (userID == null) {
							System.err.println("Unknown user trying to get secret.");
							break;
						} else if (DEBUG_COMMANDS_GETSECRET)
							System.out.println("User '" + userID + "' sent Get Secret command.");
						
						/*
						 * NOTE: Data will be of the form "name@address".
						 */
						final String data = new String(pckt.data);
						final String name = data.split("@")[0];
						final String destination = data.split("@")[1];
						final SecretData secretInfo = getSecret(name);
						
						if (secretInfo == null) {
							final byte msg_type = DecryptedPacket.CMD_MSG;
							final String msg = "[*SVR*] Secret is not available";
							
							if (DEBUG_COMMANDS_GETSECRET)
								System.out.println("Returning error message \"" + msg + "\" to user '" + userID + "'.");
							clientComms.sendPacket(msg_type, msg);
						} else {
							final String user = secretInfo.owner;
							final UserData userInfo = getUser(user);
							
							if (userInfo == null || userInfo.userThread == null) {
								final byte msg_type = DecryptedPacket.CMD_MSG;
								final String msg = "[*SVR*] Secret is not currently available";
								
								if (DEBUG_COMMANDS_GETSECRET)
									System.out.println("Returning error message \"" + msg + "\" to user '" + userID + "'.");
								clientComms.sendPacket(msg_type, msg);
							} else if (userInfo.userThread == Thread.currentThread()) {
								final byte msg_type = DecryptedPacket.CMD_MSG;
								final String msg = "[*SVR*] You can't purchase a secret from yourself!";
								
								if (DEBUG_COMMANDS_GETSECRET)
									System.out.println("Returning error message \"" + msg + "\" to user '" + userID + "'.");
								clientComms.sendPacket(msg_type, msg);
							} else {
								/* Charge the user for the secret. */
								if (!chargeUserForSecret(secretInfo))
									continue;
								
								final String fileName = secretInfo.dirname + secretInfo.filename;
								final byte msg_type = DecryptedPacket.CMD_GETSECRET;
								final String msg = fileName + "@" + destination;
								
								if (DEBUG_COMMANDS_GETSECRET)
									System.out.println("Sending get secret message \"" + msg + "\" to user \"" + user + "\".");
								userInfo.userThread.clientComms.sendPacket(msg_type, msg);
								
								/*
								 * Send public key of receiving user to sending
								 * user. Note that the receiving user does not
								 * know the public key of the sending user.
								 */
								
								/* Send the public key back to the client. */
								if (DEBUG_COMMANDS_GETPUBLICKEY)
									System.out.println("Sending user '" + name + "' the public key of user '" + userID + "'.");
								userInfo.userThread.clientComms.sendPacket(DecryptedPacket.CMD_GETPUBLICKEY, Base64.encodeBase64String(clientComms.getPeerPublicKey().getEncoded()));
								break;
							}
						}
						break;
					}
					
					/***********************************************************
					 * Get Public Key command
					 **********************************************************/
					case DecryptedPacket.CMD_GETPUBLICKEY: {
						if (userID == null) {
							System.err.println("Unknown user trying to get public key.");
							break;
						} else if (DEBUG_COMMANDS_GETPUBLICKEY)
							System.out.println("User '" + userID + "' sent get public key command.");
						
						/* Extract the user ID from the packet data. */
						final String requestedUserID = new String(pckt.data);
						if (DEBUG_COMMANDS_GETPUBLICKEY)
							System.out.println("User '" + userID + "' is requesting the public key of user '" + requestedUserID + "'.");
						
						/* Get the public key of the requested user. */
						final PublicKey key = getUser(requestedUserID).publicKey;
						
						/* Send the public key back to the client. */
						if (DEBUG_COMMANDS_GETPUBLICKEY)
							System.out.println("Sending user '" + userID + "' the public key of user '" + requestedUserID + "'.");
						clientComms.sendPacket(DecryptedPacket.CMD_GETPUBLICKEY, Base64.encodeBase64String(key.getEncoded()));
						break;
					}
					
					/*******************************************************
					 * Payment command
					 ******************************************************/
					case DecryptedPacket.CMD_PAYMENT:
						/* TODO */
						break;
					
					/*******************************************************
					 * Hashchain command
					 ******************************************************/
					case DecryptedPacket.CMD_HASHCHAIN:
						/* TODO */
						break;
					
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
		
		/*
		 * Now that a user has logged out, re-transmit the user list to all
		 * currently logged in users.
		 */
		if (DEBUG_GENERAL)
			System.out.println("Distributing user list: \"" + userListAsString() + "\"");
		else
			System.out.println("Distributing user list.\n");
		sendUserList();
		
		/* Clean up. */
		if (clientComms != null) {
			clientComms.terminateSession();
			clientComms = null;
		}
	}
	
	/**
	 * Verify the supplied {@link CryptoCreditHashChain} hash and, if valid, credit the
	 * user's account.
	 * 
	 * @param user The user whose account should be credited.
	 * @param creditsSent The number of credits declared by the {@link Client}.
	 * @param cryptoCreditHash The hash of the {@link CryptoCreditHashChain} supplied by
	 *        the {@link Client}.
	 * @return True if the credits were added to the user's account, otherwise
	 *         false.
	 */
	public static synchronized boolean addCredits(final UserData user, final int creditsSent, final byte[] cryptoCreditHash) {
		if (CryptoCreditHashChain.verify(user.lastHash, creditsSent, cryptoCreditHash)) {
			user.accountBalance += creditsSent;
			user.lastHash = cryptoCreditHash;
			return true;
		}
		
		return false;
	}
	
	/**
	 * Credit the user's account.
	 * 
	 * @param user The user whose account should be credited.
	 * @param credits The number of credits to transfer between the accounts.
	 * @return True if the credits were added to the user's account, otherwise
	 *         false.
	 */
	public static synchronized boolean addCredits(final UserData user, final int credits) {
		user.accountBalance += credits;
		return true;
	}
	
	/**
	 * Transfer credit's from one user's account to another user's account.
	 * 
	 * @param fromUser The user whose account should be deducted.
	 * @param toUser The user whose account should be credited.
	 * @param credits The number of credits to add to the user's account.
	 * @return True if the credits were added to the user's account, otherwise
	 *         false.
	 */
	public static synchronized boolean transferCredits(final UserData fromUser, final UserData toUser, final int credits) {
		if (fromUser.accountBalance >= credits) {
			fromUser.accountBalance -= credits;
			toUser.accountBalance += credits;
			return true;
		}
		
		return false;
	}
	
	/**
	 * Deduct from the user's account.
	 * 
	 * @param user The user whose account should be deducted.
	 * @param credits The number of credits to deduct from the user's account.
	 * @return True if the credits were deducted from the user's account,
	 *         otherwise false.
	 */
	public static synchronized boolean deductCredits(final UserData user, final int credits) {
		user.accountBalance -= credits;
		return true;
	}
	
	/**
	 * Receives the top of a new hash chain from the user. Checks the signature
	 * of the hash chain to ensure that the bank signed the hash chain. If the
	 * signature verification passses, then the user's last hash value is
	 * updated to the head of the new hash chain.
	 */
	public synchronized void processHashchain(final byte[] name, final byte[] credits, final byte[] topOfHashchain, final byte[] signature) {
		/* TODO */
/* @formatter:off */
		/*
		 * if the bank did sign the hash chain
		 * 		UserData thisUser = getUser(userID)
		 * 		addCredits(thisUser, credits);
		 * 		thisUser.lastHash = received top of hashchain
		 * end if
		 */
/* @formatter: on */
	}
	
	/**
	 * Charge the user for the purchase of a secret. Also credits the account of
	 * the owner of the secret.
	 * 
	 * @param secret The secret that the user wishes to purchase.
	 * @return True if the purchase should proceed, otherwise false.
	 */
	private synchronized boolean chargeUserForSecret(final SecretData secret) {
		final UserData purchasingUser = getUser(userID);
		final UserData secretOwner = getUser(secret.owner);
		
		int amountOwing;
		
		while ((amountOwing = secret.cost - purchasingUser.accountBalance) > 0) {
			/* Request payment from the client. */
			if (DEBUG_PAYMENTS)
				System.out.println("Requesting additional payment of " + amountOwing + " credits from user '" + purchasingUser.name + "' for purchase of secret \"" + secret.name + "\".");
			clientComms.sendPacket(DecryptedPacket.CMD_REQUESTPAYMENT, Integer.toString(amountOwing));
			
			/* Wait for the client to send payment. */
			if (DEBUG_PAYMENTS)
				System.out.println("Waiting for user '" + purchasingUser.name + "' to send additional payment for purchase of secret \"" + secret.name + "\".");
			DecryptedPacket pckt = new DecryptedPacket();
			while (pckt.command != DecryptedPacket.CMD_PAYMENT)
				try {
					pckt = clientComms.recvPacket();
					
					switch (pckt.command) {
/* @formatter:off */
						/*******************************************************
						 * Payment command
						 ******************************************************/
/* @formatter:on */
						case DecryptedPacket.CMD_PAYMENT:
							/*
							 * NOTE: Data will be of the form "credits;hash"
							 */
							final String data = new String(pckt.data);
							
							final int creditsSent = Integer.parseInt(data.split(";")[0]);
							final byte[] cryptoCreditHash = data.split(";")[1].getBytes();
							
							/*
							 * If the client sends a null cryptoCreditHash, then
							 * we assume that the client is no longer interested
							 * in the secret.
							 */
							if (cryptoCreditHash == null || cryptoCreditHash.length == 0)
								return false;
							else
								addCredits(purchasingUser, creditsSent, cryptoCreditHash);
							
							break;
						
						/*******************************************************
						 * Hashchain command
						 ******************************************************/
						case DecryptedPacket.CMD_HASHCHAIN:
							/* TODO */
							break;
						
						/*******************************************************
						 * Unexpected command
						 ******************************************************/
						default:
							System.err.println("Unexpected command received from server.");
					}
				} catch (final Exception e) {
					System.err.println("Error reading packet. Discarding...");
					if (DEBUG_ERROR_TRACE)
						e.printStackTrace();
				}
		}
		
		/*
		 * Deduct the funds from the users account and add the funds to the
		 * owner's account.
		 */
		transferCredits(purchasingUser, secretOwner, secret.cost);
		if (DEBUG_PAYMENTS) {
			System.out.println("Subtracted " + secret.cost + " credits from '" + purchasingUser.name + "' account.");
			System.out.println("Added " + secret.cost + " credits to '" + secret.owner + "' account.");
		}
		
		/* Let the user know that they don't owe any more money. */
		clientComms.sendPacket(DecryptedPacket.CMD_REQUESTPAYMENT, Integer.toString(0));
		if (DEBUG_PAYMENTS)
			System.out.println("Informing user '" + purchasingUser.name + "' that no additional payment is required for purchase of secret \"" + secret.name + "\".");
		
		/* Success. */
		return true;
	}
}

/******************************************************************************
 * END OF FILE: ServerThread.java
 *****************************************************************************/
