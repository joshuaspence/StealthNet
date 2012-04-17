/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet
 * FILENAME:        ProxyThread.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     The thread to be spawned for each StealthNet proxy 
 * 					connection.
 * VERSION:         1.0
 *
 *****************************************************************************/

package StealthNet;

/* Import Libraries **********************************************************/

import java.io.IOException;
import java.net.Socket;

/* ProxyThread Class Definition **********************************************/

/**
 * Represents a thread within the operating system.
 * 
 * A new instance is created for each client such that multiple clients can be
 * active concurrently. This class receives packets from one peer and forwards
 * them to the other peer. To simulate various security attacks, the packets 
 * may be altered/retransmitted/dropped.
 * 
 * @author Joshua Spence
 */
public class ProxyThread extends Thread {
	/** Debug options. */
	private static final boolean DEBUG_GENERAL               = Debug.isDebug("StealthNet.ProxyThread.General");
	private static final boolean DEBUG_ERROR_TRACE           = Debug.isDebug("StealthNet.ProxyThread.ErrorTrace") || Debug.isDebug("ErrorTrace");
	
	/** Used to separate thread ID from debug output. */
	private static final String separator = " >> ";
	
	/** Comms classes to handle communications to/from each peer. */
	private ProxyComms stealthCommsSource = null;
	private ProxyComms stealthCommsDestination = null;

	/**
	 * Constructor.
	 * 
	 * @param sourceSocket The socket that the proxy is receiving packets on.
	 * @param destinationSocket The socket that the proxy is retransmitting 
	 * packets on.
	 */
	public ProxyThread(Socket sourceSocket, Socket destinationSocket) {		
		/** Thread constructor. */
		super("StealthNet.ProxyThread");

		if (DEBUG_GENERAL) System.out.println(this.getId() + separator + "Creating a ProxyThread.");
		
		/** Create a new StealthNet.Comms instance and accept sessions. */
		stealthCommsSource = new ProxyComms();
		stealthCommsSource.acceptSession(sourceSocket);
		stealthCommsDestination = new ProxyComms();
		stealthCommsDestination.acceptSession(destinationSocket);
	}

	/**
	 * Cleans up before destroying the class.
	 * 
	 * @throws IOException
	 */
	protected void finalize() throws IOException {
		if (stealthCommsSource != null) 
			stealthCommsSource.terminateSession();
		if (stealthCommsDestination != null) 
			stealthCommsDestination.terminateSession();
	}

	/**
	 * The main function for the class. This function forwards packets from
	 * source to destination.
	 */
	public void run() {
		if (DEBUG_GENERAL) System.out.println(this.getId() + separator + "Running ProxyThread...");

		String str = new String();
		try {
			while (str != null) {
				/** Receive a StealthNet packet. */
				str = stealthCommsSource.recvString();
				
				if (str == null) {
					str = new String();
					continue;
				}
				
				stealthCommsDestination.sendString(str);
			}
		} catch (IOException e) {
			System.out.println(this.getId() + separator + "Session terminated.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
		} catch (Exception e) {
			System.err.println(this.getId() + separator + "Error running proxy thread.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
		}

		/** Clean up. */
		if (stealthCommsSource != null) {
			stealthCommsSource.terminateSession();
			stealthCommsSource = null;
		}
		if (stealthCommsDestination != null) {
			stealthCommsDestination.terminateSession();
			stealthCommsDestination = null;
		}
	}
}

/******************************************************************************
 * END OF FILE: ProxyThread.java
 *****************************************************************************/