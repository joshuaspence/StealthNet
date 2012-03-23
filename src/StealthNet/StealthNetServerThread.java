/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Stephen Gould, Matt Barrie and Ryan Junee
 *
 * PROJECT:         StealthNet
 * FILENAME:        StealthNetServerThread.java
 * AUTHORS:         Stephen Gould, Matt Barrie, Ryan Junee
 * DESCRIPTION:     Implementation of StealthNet Server for ELEC5616
 *                  programming assignment.
 *                  This code has been written for the purposes of teaching
 *                  cryptography and computer security. It is to be used as
 *                  a demonstration only. No attempt has been made to optimise
 *                  the source code.
 * VERSION:         1.0
 *
 * REVISION HISTORY:
 *
 *****************************************************************************/

package StealthNet;

/* Import Libraries **********************************************************/

import java.io.IOException;
import java.net.Socket;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;

/* StealthNetServerThread Class Definition ***********************************/

/**
 * Represents a thread within the operating system.
 * 
 * A new instance is created for each client such that multiple clients can be
 * active concurrently. This class handles StealthNetPackets and deals with them
 * accordingly.
 * 
 * @author Stephen Gould
 * @author Matt Barrie
 * @author Ryan Junee
 */
public class StealthNetServerThread extends Thread {	
	/** Set to true in build.xml to output debug messages for this class. */
	private static final boolean DEBUG = (System.getProperties().getProperty("debug." + StealthNetServerThread.class.getName()) == "true");

	/**
	 * Used to store details of other clients that this thread may want to
	 * communicate with.
	 */
	private class UserData {
		StealthNetServerThread userThread = null;
	}

	/**
	 * Client secret data.
	 */
	private class SecretData {
		String name = null;
		String description = null;
		int cost = 0;
		String owner = null; // Server knows, but clients should not
		String dirname = null;
		String filename = null;
	}

	/** A list of users, indexed by their ID. */
	private static Hashtable<String, UserData> userList = new Hashtable<String, UserData>();

	/** A list of secret data, indexed by the SecretData.name field. */
	private static Hashtable<String, SecretData> secretList = new Hashtable<String, SecretData>();

	/** The user ID for the user owning the thread. */
	private String userID = null;

	/** A StealthNetComms class to handle communications for this client. */
	private StealthNetComms stealthComms = null;

	/**
	 * Constructor.
	 * 
	 * @param socket The socket that the server is listening on.
	 */
	public StealthNetServerThread(Socket socket) {
		/** Thread constructor. */
		super("StealthNetServerThread");

		/** Create a new StealthNetComms instance and accept sessions. */
		stealthComms = new StealthNetComms();
		stealthComms.acceptSession(socket);
	}

	/**
	 * Cleans up before destroying the class.
	 * 
	 * @throws IOException
	 */
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
	 * already exists in the user list.
	 */
	private synchronized boolean addUser(String id) {
		/** Make sure the specified user doesn't already exist in the user list. */
		UserData userInfo = userList.get(id);
		
		if ((userInfo != null) && (userInfo.userThread != null)) {
			return false;
		} else {
			/** Create new user data for the specified user. */
			userInfo = new UserData();
			userInfo.userThread = this;
			userList.put(id, userInfo);
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
	private synchronized boolean addSecret(SecretData t) {
		/** Make sure the secret doesn't already exist in the secret list. */
		final SecretData secretInfo = secretList.get(t.name);
		
		if (secretInfo != null) {
			return false;
		} else {
			/** Add the secret data to the secret list. */
			secretList.put(t.name, t);
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
	private synchronized boolean removeUser(String id) {
		UserData userInfo = userList.get(id);
		if (userInfo != null) {
			userInfo.userThread = null;
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Remove secret data from this thread's secret list.
	 * 
	 * @param name The name of the secret data to remove.
	 * @return True on success, false on failure.
	 */
	@SuppressWarnings("unused")
	private synchronized boolean removeSecret(String name) {
		secretList.remove(name);
		return true;
	}

	/**
	 * Convert the user list to a String.
	 * 
	 * @return A String representing the user list.
	 */
	private synchronized String userListAsString() {
		String userTable = "";
		Enumeration<String> i = userList.keys();
		
		while (i.hasMoreElements()) {
			final String userKey = i.nextElement();
			final UserData userInfo = userList.get(userKey);

			userTable += userKey + ", ";
			if ((userInfo != null) && (userInfo.userThread != null))
				userTable += "true";
			else
				userTable += "false";
			userTable += "\n";
		}

		return userTable;
	}

	/**
	 * Convert the secret list to a String.
	 * 
	 * @return A String representing the secret list.
	 */
	private synchronized String secretListAsString() {
		String secretTable = "";
		Enumeration<String> i = secretList.keys();
		
		while (i.hasMoreElements()) {
			final String secretKey = i.nextElement();
			final SecretData secretInfo = secretList.get(secretKey);
			
			secretTable += secretKey + ";";
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
		Enumeration<String> i = userList.keys();
		final String userTable = userListAsString();

		while (i.hasMoreElements()) {
			final String userKey = i.nextElement();
			UserData userInfo = userList.get(userKey);

			if ((userInfo != null) && (userInfo.userThread != null)) {
				if (userInfo.userThread.stealthComms == null)
					userInfo.userThread = null;
				else
					/** Send this user the user list in a StealthNetPacket. */
					userInfo.userThread.stealthComms.sendPacket(StealthNetPacket.CMD_LIST, userTable);
			}
		}
	}

	/**
	 * Send the secret list (as a String) to all current users. Sent to all
	 * logged in users (including the new user) whenever a new user logs on.
	 */
	private synchronized void sendSecretList() {
		Enumeration<String> i = userList.keys();
		final String secretTable = secretListAsString();

		while (i.hasMoreElements()) {
			final String userKey = i.nextElement();
			UserData userInfo = userList.get(userKey);

			if ((userInfo != null) && (userInfo.userThread != null)) {
				if (userInfo.userThread.stealthComms == null)
					userInfo.userThread = null;
				else
					/** Send this user the secret list in a StealthNetPacket. */
					userInfo.userThread.stealthComms.sendPacket(StealthNetPacket.CMD_SECRETLIST, secretTable);
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
	 * If the packet contains the message command, then the message contained in
	 * the packet data is sent to all logged in users.
	 * 
	 * If the packet contains the chat command, then a chat session is started
	 * between the specified users.
	 * 
	 * If the packet contains the FTP command, then a file transfer session is
	 * started between the specified users.
	 * 
	 * If the packet contains the create secret command, then we create secret
	 * data from the StealthNetPacket data, and retransmit the list of secrets
	 * to all currently logged in users.
	 */
	public void run() {
		if (DEBUG) System.out.println("Running StealthNetServerThread...");

		StealthNetPacket pckt = new StealthNetPacket();

		try {
			while (pckt.command != StealthNetPacket.CMD_LOGOUT) {
				/** Receive a StealthNetPacket. */
				pckt = stealthComms.recvPacket();
				
				String userKey, iAddr, msg;
		        UserData userInfo;
				byte msg_type;

				/** Perform the relevant action based on the packet command. */
				switch (pckt.command) {
					/***********************************************************
					 * NULL command
					 **********************************************************/
					case StealthNetPacket.CMD_NULL:
						System.out.println("Received NULL command.");
						break;
	
					/***********************************************************
					 * Login command
					 **********************************************************/
					case StealthNetPacket.CMD_LOGIN:
						if (DEBUG) System.out.println("Received login command.");
	
						if (userID != null) {
							/** A user is already logged in. */
							System.out.println("User " + userID + " trying to log in twice.");
							break;
						}
						
						/** Extract the user ID from the packet data. */
						userID = new String(pckt.data);

						/** Log the user in. */
						if (!addUser(userID)) {
							System.out.println("User \"" + userID + "\" is already logged in.");

							/** Cancel the current login attempt. */
							pckt.command = StealthNetPacket.CMD_LOGOUT;
							userID = null;
						} else {
							System.out.println("User \"" + userID + "\" has logged in.");

							if (DEBUG) {
								System.out.println("Sending user list...");

								final String userTable = userListAsString();
								System.out.println("User list: \"" + userTable + "\"");
							}
							sendUserList();

							if (DEBUG) {
								System.out.println("Sending secret list...");

								final String secretTable = secretListAsString();
								System.out.println("Secret list: \"" + secretTable + "\"");
							}
							sendSecretList();
						}
						break;
						
					/***********************************************************
					 * Logout command
					 **********************************************************/
					case StealthNetPacket.CMD_LOGOUT:
						if (DEBUG) System.out.println("Received logout command.");
	
						if (userID == null)
							System.out.println("Unknown user trying to log out.");
						else
							System.out.println("User \"" + userID + "\" has logged out.");
	
						/** The code will now break out of the while loop. */
						break;
	
					/***********************************************************
					 * Message command
					 **********************************************************/
					case StealthNetPacket.CMD_MSG:
						if (DEBUG) System.out.println("Received message command.");
	
						if (userID == null) {
							System.out.println("Unknown user trying to send message.");
							break;
						}
						
						msg = new String(pckt.data);
						msg = "[" + userID + "] " + msg;

						/** Send the message to all users. */
						if (DEBUG) System.out.println("Sending message (\"" + msg + "\").");
						Enumeration<String> i = userList.keys();
						while (i.hasMoreElements()) {
							userKey = i.nextElement();
							userInfo = userList.get(userKey);

							if ((userInfo != null) && (userInfo.userThread != null))
								userInfo.userThread.stealthComms.sendPacket(StealthNetPacket.CMD_MSG, msg);
						}
						break;
	
					/***********************************************************
					 * Chat command
					 **********************************************************/
					case StealthNetPacket.CMD_CHAT:
						if (DEBUG) System.out.println("Received chat command.");
	
						if (userID == null) {
							System.out.println("Unknown user trying to chat.");
							break;
						}
						
						userKey = new String(pckt.data);
						iAddr = userKey.substring(userKey.lastIndexOf("@") + 1);
						userKey = userKey.substring(0, userKey.length() - iAddr.length() - 1);
						userInfo = userList.get(userKey);
						
						if ((userInfo == null) || (userInfo.userThread == null)) {
							msg_type = StealthNetPacket.CMD_MSG;
							msg = "[*SVR*] User not logged in";
						} else if (userInfo.userThread == Thread.currentThread()) {
							msg_type = StealthNetPacket.CMD_MSG;
							msg = "[*SVR*] Cannot chat to self";
							
							stealthComms.sendPacket(msg_type, msg);
						} else {
							msg_type = StealthNetPacket.CMD_CHAT;
							msg = userID + "@" + iAddr;
							
							if (DEBUG) System.out.println("Sending chat message (\"" + msg + "\").");
							userInfo.userThread.stealthComms.sendPacket(msg_type, msg);
						}
						
						break;
	
					/***********************************************************
					 * FTP command
					 **********************************************************/
					case StealthNetPacket.CMD_FTP:
						if (DEBUG) System.out.println("Received FTP command.");
	
						if (userID == null) {
							System.out.println("Unknown user trying to transfer file.");
							break;
						}
						
						userKey = new String(pckt.data);
						iAddr = userKey.substring(userKey.lastIndexOf("@") + 1);
						userKey = userKey.substring(0, userKey.length() - iAddr.length() - 1);
						userInfo = userList.get(userKey);
						
						if ((userInfo == null) || (userInfo.userThread == null)) {
							msg_type = StealthNetPacket.CMD_MSG;
							msg = "[*SVR*] User not logged in";
							
							stealthComms.sendPacket(msg_type, msg);
						} else if (userInfo.userThread == Thread.currentThread()) {
							msg_type = StealthNetPacket.CMD_MSG;
							msg = "[*SVR*] Cannot ftp to self";
							
							stealthComms.sendPacket(msg_type, msg);
						} else {
							msg_type = StealthNetPacket.CMD_FTP;
							msg = userID + "@" + iAddr;
							
							userInfo.userThread.stealthComms.sendPacket(msg_type, msg);
						}
						break;
	
					/***********************************************************
					 * Create Secret command
					 **********************************************************/
					case StealthNetPacket.CMD_CREATESECRET:
						if (DEBUG) System.out.println("Received create secret command.");
	
						if (userID == null) {
							System.out.println("Unknown user trying to create secret.");
							break;
						}
						
						/** Depacketise the create command. */
						SecretData t = new SecretData();
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
						System.out.println("Added secret.\n");

						System.out.println("Sending secret list from server.\n");
						if (DEBUG) {
							final String secretTable = secretListAsString();
							System.out.println("Secret list is \"" + secretTable + "\"");
						}
						sendSecretList();
						break;
	
					/***********************************************************
					 * Get Secret command
					 **********************************************************/
					case StealthNetPacket.CMD_GETSECRET:
						if (DEBUG) System.out.println("Received Get Secret command.");
	
						if (userID == null) {
							System.out.println("Unknown user trying to get secret.");
							break;
						}
						
						final String data = new String(pckt.data);
						iAddr = data.substring(data.lastIndexOf("@") + 1);
						final String name = data.substring(0, data.length() - iAddr.length() - 1);
						final SecretData secretInfo = secretList.get(name);
						
						if (secretInfo == null) {
							msg_type = StealthNetPacket.CMD_MSG;
							msg = "[*SVR*] Secret is not available";
						} else {
							final String user = secretInfo.owner;
							userInfo = userList.get(user);

							if ((userInfo == null) || (userInfo.userThread == null)) {
								msg_type = StealthNetPacket.CMD_MSG;
								msg = "[*SVR*] Secret is not currently available";
								
								stealthComms.sendPacket(msg_type, msg);
							} else if (userInfo.userThread == Thread.currentThread()) {
								msg_type = StealthNetPacket.CMD_MSG;
								msg = "[*SVR*] You can't purchase a secret from yourself!";
								
								stealthComms.sendPacket(msg_type, msg);
							} else {
								final String fName = secretInfo.dirname + secretInfo.filename;
								msg_type = StealthNetPacket.CMD_GETSECRET;
								msg = fName + "@" + iAddr;
								
								userInfo.userThread.stealthComms.sendPacket(msg_type, msg);
							}
						}
						break;
	
					/***********************************************************
					 * Unknown command
					 **********************************************************/
					default:
						System.out.println("Unrecognised command.");
				}
			}
		} catch (IOException e) {
			System.out.println("User \"" + userID + "\" session terminated.");
			if (DEBUG) e.printStackTrace();
		} catch (Exception e) {
			System.err.println("Error running server thread.");
			if (DEBUG) e.printStackTrace();
		}

		/**
		 * We only reach this code when a user is logging out, so lets remove
		 * the logged out user from the user list.
		 */
		if (userID != null) {
			if (DEBUG) System.out.println("Removing user " + userID + " from user list.");
			removeUser(userID);
		}
		
		/**
		 * Now that a user has logged out, re-transmit the user list to all
		 * currently logged in users.
		 */
		if (DEBUG) System.out.println("Sending user list...");
		sendUserList();

		/** Clean up. */
		if (stealthComms != null) {
			stealthComms.terminateSession();
			stealthComms = null;
		}
	}
}

/******************************************************************************
 * END OF FILE: StealthNetServerThread.java
 *****************************************************************************/