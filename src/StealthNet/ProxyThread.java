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
import java.math.BigInteger;
import java.net.Socket;
import java.net.SocketException;
import java.util.Random;

/* StealthNet.ProxyThread Class Definition ***********************************/

/**
 * Represents a thread within the operating system for communications between
 * the StealthNet proxy and a client/server.
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
	private static final boolean DEBUG_GENERAL     = Debug.isDebug("StealthNet.ProxyThread.General");
	private static final boolean DEBUG_ERROR_TRACE = Debug.isDebug("StealthNet.ProxyThread.ErrorTrace") || Debug.isDebug("ErrorTrace");
	
	/** How malicious should we be? */
	private static final boolean isMalicious = false;			/** True to enable simulated security attacks. */
	private static final long noMaliciousnessPacketCount = 5;	/** Don't perform any malicious activity for the first X packets. */
	private static final int replayProbability = 50;			/** Probability (as an integer out of 100) of a replay attack after the first X packets. */
	private static final int corruptionProbability = 50;		/** Probability (as an integer out of 100) of a corruption attack after the first X packets. */
	
	/** Used to separate thread ID from debug output. */
	private static final String separator = " >> ";
	
	/** ProxyComms classes to handle communications to/from each peer. */
	private ProxyComms stealthCommsSource = null;
	private ProxyComms stealthCommsDestination = null;
	
	/** Paired thread (to be killed when this thread terminates). */
	private ProxyThread pairedThread;
	
	/** Boolean to indicate that this thread should be stopped. */
	private boolean shouldStop = false;

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
		
		/** Create a new ProxyComms instance and accept sessions. */
		stealthCommsSource = new ProxyComms();
		stealthCommsSource.acceptSession(sourceSocket);
		stealthCommsDestination = new ProxyComms();
		stealthCommsDestination.acceptSession(destinationSocket);
	}
	
	/**
	 * Set a ProxyThread to be terminated when this thread terminates.
	 * 
	 * @param pair The ProxyThread to be paired with this thread.
	 */
	public void setPairedThread(ProxyThread pair) {
		pairedThread = pair;
	}
	
	/**
	 * Set whether or not a thread should stop executing.
	 * 
	 * @param stop True if this thread should stop executing, otherwise false.
	 */
	private synchronized void setShouldStop(boolean stop) {
		shouldStop = stop;
	}
	
	/**
	 * Checks if a thread should stop executing.
	 * 
	 * @return True if the thread should stop executing, otherwise false.
	 */
	private synchronized boolean getShouldStop() {
		return shouldStop;
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
	@SuppressWarnings("unused")
	public void run() {
		if (DEBUG_GENERAL) System.out.println(this.getId() + separator + "Running ProxyThread...");

		String str = new String();
		Random rnd = new Random();
		BigInteger counter = BigInteger.ZERO;
		
		try {
			while (str != null && !getShouldStop()) {
				/** Receive a StealthNet packet. */
				str = stealthCommsSource.recvString();
				
				if (str == null)
					break;
				
				counter = counter.add(BigInteger.ONE);
				System.out.println(counter);
				/** Decide whether or not to corrupt a message. */
				if (isMalicious && (counter.compareTo(BigInteger.valueOf(noMaliciousnessPacketCount)) > 0) && ((rnd.nextInt() % 100) < corruptionProbability)) {
					if (DEBUG_GENERAL) System.out.println(this.getId() + separator + "Corrupting packet...");
					stealthCommsDestination.sendString(new StringBuffer(str).reverse().toString());
				} else {
					stealthCommsDestination.sendString(str);
				}
				
				/** Decide whether or not to replay a message. */
				if (isMalicious && (counter.compareTo(BigInteger.valueOf(noMaliciousnessPacketCount)) > 0) && (rnd.nextInt() % 100) < replayProbability) {
					if (DEBUG_GENERAL) System.out.println(this.getId() + separator + "Replaying last packet...");
					stealthCommsDestination.sendString(str);
				}
				
			}
		} catch (SocketException e) {
			/** This is a fairly "clean" exit. */
			System.out.println(this.getId() + separator + "Session terminated.");
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
		
		/** Kill the other thread. */
		if (pairedThread != null && !pairedThread.getShouldStop()) {
			if (DEBUG_GENERAL) System.out.println("Killing paired thread.");
			pairedThread.setShouldStop(true);
		}
	}
}

/******************************************************************************
 * END OF FILE: ProxyThread.java
 *****************************************************************************/