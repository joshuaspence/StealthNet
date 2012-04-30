/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet
 * FILENAME:        ProxyThread.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     The thread to be spawned for each StealthNet proxy 
 * 					connection.
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
 * A ProxyThread is "paired" with another ProxyThread such that when one thread
 * ends, the paired thread can be ended as well. This is because for a single 
 * client<=>server connection, for example, two ProxyThreads will be created -
 * one to handle the client->server communications and another to handle the
 * server->client communications.
 * 
 * @author Joshua Spence
 */
public class ProxyThread extends Thread {
	/** Debug options. */
	private static final boolean DEBUG_GENERAL     = Debug.isDebug("StealthNet.ProxyThread.General");
	private static final boolean DEBUG_ERROR_TRACE = Debug.isDebug("StealthNet.ProxyThread.ErrorTrace") || Debug.isDebug("ErrorTrace");
	
	/** How malicious should we be? */
	
	/** True to enable simulated security attacks. */
	public static final boolean isMalicious = System.getProperty("StealthNet.Proxy.Malicious", "false").equals("true");
	
	/** Don't perform any malicious activity for the first X packets. */
	private static final long noMaliciousPacketCount = 5;
	
	/** Probability (as an integer out of 100) of a replay attack after the first X packets. */
	private static final int replayProbability = 25;	
	
	/** Probability (as an integer out of 100) of a corruption attack after the first X packets. */
	private static final int corruptionProbability = 25;
	
	/** Used to separate thread ID from debug output. */
	private static final String THREADID_PREFIX = "Thread ";
	private static final String THREADID_SUFFIX = " >> ";
	
	/** ProxyComms classes to handle communications to/from each peer. */
	private ProxyComms stealthCommsSource = null;
	private ProxyComms stealthCommsDestination = null;
	
	/** Paired thread (to be killed when this thread terminates). */
	private ProxyThread pairedThread;
	
	/** 
	 * Boolean to indicate that this thread should be stopped. Set by this 
	 * thread's "paired" thread. 
	 */
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

		if (DEBUG_GENERAL) System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Creating a ProxyThread.");
		
		/** Create a new ProxyComms instance and accept sessions. */
		stealthCommsSource = new ProxyComms();
		stealthCommsSource.acceptSession(sourceSocket);
		stealthCommsDestination = new ProxyComms();
		stealthCommsDestination.acceptSession(destinationSocket);
	}
	
	/**
	 * Set a ProxyThread to be terminated when this thread terminates.
	 * 
	 * @param thread The ProxyThread to be paired with this thread.
	 */
	public void setPairedThread(ProxyThread thread) {
		pairedThread = thread;
	}
	
	/**
	 * Set whether or not a thread should stop executing. This should be set by
	 * this thread's "paired" thread when the paired thread itself wishes to
	 * terminate.
	 * 
	 * @param stop True if this thread should stop executing, otherwise false.
	 */
	private synchronized void setShouldStop(boolean stop) {
		shouldStop = stop;
	}
	
	/**
	 * Checks if a thread should stop executing. This should be called within 
	 * this thread to provide thread-safe access to the `shouldStop' boolean
	 * variable, which may be set by this thread's paired thread.
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
	 * 
	 * If isMalicious is true, then the proxy will attempt to randomly simulate
	 * various security attacks. After the initial noMaliciousPacketCount 
	 * received packets (during which no malicious activity will occur - to 
	 * allow the communicating parties to perform various security protocols),
	 * the server will randomly simulate a security attack with some 
	 * probability based on a pseudo-random number generator.  
	 */
	public void run() {
		if (DEBUG_GENERAL) System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Running ProxyThread...");

		String packetString = new String();
		final Random rnd = new Random();
		BigInteger pcktCounter = BigInteger.ZERO;
		
		try {
			while (packetString != null && !getShouldStop()) {
				/** Receive a StealthNet packet. */
				packetString = stealthCommsSource.recvString();
				
				if (packetString == null)
					break;
				
				/** Increment the packet counter. */
				pcktCounter = pcktCounter.add(BigInteger.ONE);
				
				/** Decide whether or not to corrupt a message. */
				if (isMalicious && pcktCounter.compareTo(BigInteger.valueOf(noMaliciousPacketCount)) > 0 && (rnd.nextInt() % 100) < corruptionProbability) {
					if (DEBUG_GENERAL) System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Corrupting packet...");
					
					/** Simply reverse the packet string. */
					stealthCommsDestination.sendString(new StringBuffer(packetString).reverse().toString());
				} else {
					stealthCommsDestination.sendString(packetString);
				}
				
				/** Decide whether or not to replay a message. */
				if (isMalicious && pcktCounter.compareTo(BigInteger.valueOf(noMaliciousPacketCount)) > 0 && (rnd.nextInt() % 100) < replayProbability) {
					if (DEBUG_GENERAL) System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Replaying last packet...");
					stealthCommsDestination.sendString(packetString);
				}
				
			}
		} catch (SocketException e) {
			/** 
			 * This is a fairly "clean" exit which can, but hopefully won't, 
			 * occur.
			 */
			System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Session terminated.");
		} catch (IOException e) {
			System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Session terminated.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
		} catch (Exception e) {
			System.err.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Error running proxy thread.");
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
		
		/** Kill the paired thread. */
		if ((pairedThread != null) && (!pairedThread.getShouldStop())) {
			if (DEBUG_GENERAL) System.out.println(THREADID_PREFIX + this.getId() + THREADID_SUFFIX + "Killing paired thread " + pairedThread.getId() + ".");
			pairedThread.setShouldStop(true);
		}
	}
}

/******************************************************************************
 * END OF FILE: ProxyThread.java
 *****************************************************************************/