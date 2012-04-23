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
import java.util.Hashtable;

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
	
	/** Used to separate thread ID from debug output. */
	private static final String THREADID_PREFIX = "Thread ";
	private static final String THREADID_SUFFIX = " >> ";
	
	/**
	 * Used to store details of the clients available funds.
	 */
	private class UserBankAccount {
		BankThread userThread = null;
	}

	/** A list of users, indexed by their ID. */
	private static final Hashtable<String, UserBankAccount> userList = new Hashtable<String, UserBankAccount>();
	
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
		super("StealthNet.ServerThread");

		if (DEBUG_GENERAL) System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Creating a ServerThread.");
		
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
		        UserBankAccount userBankAccount;
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