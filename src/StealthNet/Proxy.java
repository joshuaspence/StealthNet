/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet
 * FILENAME:        Proxy.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     A proxy for StealthNet that can be used to simulate various 
 * 					security attacks; or just for normal StealthNet operation.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet;

/* Import Libraries ******************************************************** */

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/* StealthNet.Proxy Class Definition *************************************** */

/**
 * A proxy for StealthNet that can be used to simulate various security attacks.
 * The proxy simply accepts {@link Server}-bound connections from a
 * {@link Client} and creates its own connection to the {@link Server} on behalf
 * of the {@link Client}. Any messages from the {@link Client} to the
 * {@link Server} (and vice versa) will be relayed through the proxy.
 * 
 * @author Joshua Spence
 * @see ProxyThread
 */
public class Proxy {
	/* Debug options. */
	private static final boolean DEBUG_GENERAL = Debug.isDebug("StealthNet.Proxy.General");
	private static final boolean DEBUG_ERROR_TRACE = Debug.isDebug("StealthNet.Proxy.ErrorTrace") || Debug.isDebug("ErrorTrace");
	
	/* Use the BouncyCastle API. */
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	/**
	 * The main proxy function.
	 * 
	 * @param args The command line arguments.
	 * @throws IOException
	 */
	public static void main(final String[] args) {
		/* Port that the proxy is listening on. */
		int proxyPort = ProxyComms.DEFAULT_PROXYPORT;
		
		/* Check if a port number was specified at the command line. */
		if (args.length > 0)
			try {
				proxyPort = Integer.parseInt(args[0]);
				
				/* Check for a valid port number. */
				if (proxyPort <= 0 || proxyPort > 65535)
					throw new NumberFormatException("Invalid port number: " + proxyPort);
			} catch (final NumberFormatException e) {
				System.err.println(e.getMessage());
				if (DEBUG_ERROR_TRACE)
					e.printStackTrace();
				System.exit(1);
			}
		
		/* Hostname of the REAL server. */
		String serverHostname = Comms.DEFAULT_SERVERNAME;
		
		/* Port that the server is listening on. */
		int serverPort = Comms.DEFAULT_SERVERPORT;
		
		/* Check if a host and port was specified at the command line. */
		if (args.length > 0)
			try {
				final String[] input = args[0].split(":", 2);
				
				serverHostname = input[0];
				if (input.length > 1)
					serverPort = Integer.parseInt(input[1]);
				
				if (serverPort <= 0 || serverPort > 65535)
					throw new NumberFormatException("Invalid port number: " + serverPort);
			} catch (final NumberFormatException e) {
				System.err.println(e.getMessage());
				if (DEBUG_ERROR_TRACE)
					e.printStackTrace();
				System.exit(1);
			}
		
		/* Try to create a server socket listening on a specified port. */
		ServerSocket svrSocket = null;
		try {
			svrSocket = new ServerSocket(proxyPort);
		} catch (final IOException e) {
			System.err.println("Could not listen on port " + proxyPort);
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
			System.exit(1);
		}
		
		if (DEBUG_GENERAL)
			System.out.println((ProxyThread.isMalicious ? "Malicious proxy" : "Proxy") + " is listening on port " + proxyPort + ".");
		System.out.println((ProxyThread.isMalicious ? "Malicious proxy" : "Proxy") + " online...");
		
		/*
		 * Wait for and accept connections on the proxy server socket. Create
		 * two new threads for each connection - one to handle communication in
		 * each direction.
		 */
		while (true)
			try {
				final Socket clientConn = svrSocket.accept();
				final Socket serverConn = new Socket(serverHostname, serverPort);
				
				final ProxyThread clientThread = new ProxyThread(clientConn, serverConn);
				final ProxyThread serverThread = new ProxyThread(serverConn, clientConn);
				
				/*
				 * Mark the threads as paired so that they can kill each other.
				 */
				clientThread.setPairedThread(serverThread);
				serverThread.setPairedThread(clientThread);
				
				/* Start thread execution. */
				clientThread.start();
				serverThread.start();
				
				if (DEBUG_GENERAL) {
					System.out.println("Proxy accepted connection from " + clientConn.getInetAddress() + " on port " + clientConn.getPort() + ".");
					System.out.println("Proxy created connection to " + serverConn.getInetAddress() + " on port " + serverConn.getPort() + ".");
				} else
					System.out.println("Proxy accepted connection...");
			} catch (final Exception e) {
				System.err.println("Error accepting new client connection. Dropping connection...");
				if (DEBUG_ERROR_TRACE)
					e.printStackTrace();
			}
	}
}

/******************************************************************************
 * END OF FILE: Proxy.java
 *****************************************************************************/
