/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet
 * FILENAME:        Proxy.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     A proxy for StealthNet that can be used to simulate various 
 * 					security attacks.
 * VERSION:         1.0
 *
 * REVISION HISTORY:
 *
 *****************************************************************************/

package StealthNet;

/* Import Libraries **********************************************************/

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/* Proxy Class Definition ****************************************************/

/**
 * A proxy for StealthNet that can be used to simulate various security attacks.
 * The proxy simply accepts server-bound connections from a client and creates 
 * its own connection to the server on behalf of the client. Any messages from 
 * the client to the server (and vice versa) will be relayed through the proxy.
 * 
 * @author Joshua Spence
 */
public class Proxy {
	/** Debug options. */
	private static final boolean DEBUG_GENERAL     = Debug.isDebug("StealthNet.Proxy.General");
	private static final boolean DEBUG_ERROR_TRACE = Debug.isDebug("StealthNet.Proxy.ErrorTrace") || Debug.isDebug("ErrorTrace");
	
	/** 
	 * The main Proxy function.
	 * 
	 * @param args The command line arguments.
	 * @throws IOException
	 */
    public static void main(String[] args) throws IOException {
    	/** Port that the proxy is listening on. */
    	int proxyPort = Comms.DEFAULT_PROXYPORT;
    	
    	/** Check if a port number was specified at the command line. */
    	if (args.length > 0) {
    		try {
    			proxyPort = Integer.parseInt(args[0]);
    			
    			/** Check for a valid port number. */
    			if (proxyPort <= 0 || proxyPort > 65535)
    				throw new NumberFormatException("Invalid port number: " + proxyPort);
    		} catch (NumberFormatException e) {
    			System.err.println(e.getMessage());
    			if (DEBUG_ERROR_TRACE) e.printStackTrace();
                System.exit(1);
    		}
    	}
    	
    	/** Hostname of the server. */
    	String serverHostname = Comms.DEFAULT_SERVERNAME;
    	
    	/** Port that the server is listening on. */
    	int serverPort = Comms.DEFAULT_SERVERPORT;
    	
    	/** Check if a host and port was specified at the command line. */
    	if (args.length > 0) {
    		try {
    			String[] input = args[0].split(":", 2);
    			
    			serverHostname = input[0];
    			if (input.length > 1)
    				serverPort = Integer.parseInt(input[1]);
    			
    			if (serverPort <= 0 || serverPort > 65535)
    				throw new NumberFormatException("Invalid port number: " + serverPort);
    		} catch (NumberFormatException e) {
    			System.err.println(e.getMessage());
    			if (DEBUG_ERROR_TRACE) e.printStackTrace();
                System.exit(1);
    		}
    	}
    	
    	/** Try to create a server socket listening on a specified port. */
        ServerSocket svrSocket = null;
        try {
            svrSocket = new ServerSocket(proxyPort);
        } catch (IOException e) {
            System.err.println("Could not listen on port " + proxyPort);
            if (DEBUG_ERROR_TRACE) e.printStackTrace();
            System.exit(1);
        }

        if (DEBUG_GENERAL) System.out.println("Proxy server is listening on port " + proxyPort + ".");
        System.out.println("Proxy server online...");
        
        /** 
         * Wait for and accept connections on the proxy server socket. Create a 
         * new thread for each connection.
         */
        while (true) {
        	final Socket clientConn = svrSocket.accept();
        	final Socket serverConn = new Socket(serverHostname, serverPort);
        	final ProxyThread clientThread = new ProxyThread(clientConn, serverConn);
        	final ProxyThread serverThread = new ProxyThread(serverConn,clientConn);
        	clientThread.start();
        	serverThread.start();
            
            if (DEBUG_GENERAL) {
            	System.out.println("Proxy accepted connection from " + clientConn.getInetAddress() + " on port " + clientConn.getPort() + ".");
            	System.out.println("Proxy created connection to " + serverConn.getInetAddress() + " on port " + serverConn.getPort() + ".");
            } else {
            	System.out.println("Proxy accepted connection...");
            }
        }
    }
}

/******************************************************************************
 * END OF FILE:     Proxy.java
 *****************************************************************************/