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

package StealthNet;

/* Import Libraries **********************************************************/

import java.io.IOException;
import java.net.Socket;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;

/* StealthNet.BankThread Class Definition ************************************/

/**
 * TODO
 * 
 * @author Joshua Spence
 */
public class BankThread extends Thread {
	/** Debug options. */
	private static final boolean DEBUG_GENERAL               = Debug.isDebug("StealthNet.BankThread.General");
	private static final boolean DEBUG_ERROR_TRACE           = Debug.isDebug("StealthNet.BankThread.ErrorTrace") || Debug.isDebug("ErrorTrace");
	private static final boolean DEBUG_COMMANDS_NULL         = Debug.isDebug("StealthNet.BankThread.Commands.Null");
	private static final boolean DEBUG_COMMANDS_LOGIN        = Debug.isDebug("StealthNet.BankThread.Commands.Login");
	private static final boolean DEBUG_COMMANDS_LOGOUT       = Debug.isDebug("StealthNet.BankThread.Commands.Logout");
	
	/** Used to separate thread ID from debug output. */
	private static final String THREADID_PREFIX = "Thread ";
	private static final String THREADID_SUFFIX = " >> ";
	
	/** Constants. */
	private static final int INITIAL_BALANCE = 100;
	
	/**
	 * Used to store details of the clients available funds.
	 */
	private class UserBankAccount {
		BankThread userThread = null;
		int balance = INITIAL_BALANCE;
	}

	/** A list of users, indexed by their ID. */
	private static final Hashtable<String, UserBankAccount> userAccounts = new Hashtable<String, UserBankAccount>();
	
	/** The user ID for the user owning the thread. */
	private String userID = null;

	/** A StealthNetComms class to handle communications for this client. */
	private Comms stealthComms = null;

	/**
	 * Constructor.
	 * 
	 * @param socket The socket that the server is listening on.
	 */
	public BankThread(Socket socket) {		
		/** Thread constructor. */
		super("StealthNet.BankThread");

		if (DEBUG_GENERAL) System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Creating a BankThread.");
		
		/** Create a new StealthNet.Comms instance and accept sessions. */
		stealthComms = new Comms();
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
	 * Add a user to the user list. Used to log the specified user into the
	 * StealthNet bank.
	 * 
	 * @param id The ID of the user to add.
	 * @return True on success, false on failure or if the specified user 
	 * already exists in the user list.
	 */
	private synchronized boolean addUser(String id) {
		/** Make sure the specified user doesn't already exist in the user list. */
		UserBankAccount userAccount = userAccounts.get(id);
		
		if ((userAccount != null) && (userAccount.userThread != null)) {
			return false;
		} else {
			/** Create new user data for the specified user. */
			userAccount = new UserBankAccount();
			userAccount.userThread = this;
			userAccounts.put(id, userAccount);
			
			if (DEBUG_GENERAL) System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Added user \"" + id + "\" to the user list.");
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
		final UserBankAccount userAccount = userAccounts.get(id);
		if (userAccount != null) {
			userAccount.userThread = null;
			if (DEBUG_GENERAL) System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Removed user \"" + id + "\" from the user list.");
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * The main function for the class. This function handles all type of
	 * StealthNet packets.
	 * 
	 * TODO
	 */
	public void run() {
		if (DEBUG_GENERAL) System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Running BankThread...");

		DecryptedPacket pckt = new DecryptedPacket();
		try {
			while (pckt.command != DecryptedPacket.CMD_LOGOUT) {
				/** Receive a StealthNet.Packet. */
				pckt = stealthComms.recvPacket();
				
				if (pckt == null)
					break;
				
				String userKey, iAddr, msg;
		        UserBankAccount userAccount;
				byte msg_type;
				
				if (DEBUG_GENERAL) {
					if (pckt.data == null)	 System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Received packet. Packet command: " + DecryptedPacket.getCommandName(pckt.command) + ".");
					else	                 System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Receiced packet. Packet command: " + DecryptedPacket.getCommandName(pckt.command) + ". Packet data: \"" + new String(pckt.data) + "\".");
				}

				/** Perform the relevant action based on the packet command. */
				switch (pckt.command) {						
					/***********************************************************
					 * NULL command
					 **********************************************************/
					case DecryptedPacket.CMD_NULL:
						if (DEBUG_COMMANDS_NULL) System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Received NULL command.");
						break;
	
					/***********************************************************
					 * Login command
					 **********************************************************/
					case DecryptedPacket.CMD_LOGIN:
						if (DEBUG_COMMANDS_LOGIN) System.out.println("Received login command.");
	
						if (userID != null) {
							/** A user is already logged in. */
							System.err.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "User \"" + userID + "\" trying to log in twice.");
							break;
						}
						
						/** Extract the user ID from the packet data. */
						userID = new String(pckt.data);

						/** Log the user in. */
						if (!addUser(userID)) {
							System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "User \"" + userID + "\" is already logged in.");

							/** Cancel the current login attempt. */
							pckt.command = DecryptedPacket.CMD_LOGOUT;
							userID = null;
						} else {
							System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "User \"" + userID + "\" has logged in.");
						}
						break;
						
					/***********************************************************
					 * Logout command
					 **********************************************************/
					case DecryptedPacket.CMD_LOGOUT:
						if (DEBUG_COMMANDS_LOGOUT) System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Received logout command.");
	
						if (userID == null)
							System.err.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Unknown user trying to log out.");
						else
							System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "User \"" + userID + "\" has logged out.");
	
						/** The code will now break out of the while loop. */
						break;
	
	
					/***********************************************************
					 * Unknown command
					 **********************************************************/
					default:
						System.err.println("Unrecognised command.");
				}
			}
		} catch (IOException e) {
			System.err.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "User \"" + userID + "\" session terminated.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
		} catch (Exception e) {
			System.err.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Error running server thread.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
		}

		/**
		 * We only reach this code when a user is logging out, so lets remove
		 * the logged out user from the user list.
		 */
		if (userID != null)
			removeUser(userID);

		/** Clean up. */
		if (stealthComms != null) {
			stealthComms.terminateSession();
			stealthComms = null;
		}
	}
}

/******************************************************************************
 * END OF FILE: BankThread.java
 *****************************************************************************/