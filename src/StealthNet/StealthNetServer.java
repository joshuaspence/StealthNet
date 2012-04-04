/******************************************************************************
 * ELEC5616/NETS3016
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie and Stephen Gould
 *
 * PROJECT:         StealthNet
 * FILENAME:        StealthNetServer.java
 * AUTHORS:         Matt Barrie and Stephen Gould
 * DESCRIPTION:     Implementation of StealthNet Server for ELEC5616/NETS3016
 *                  programming assignment.
 *                  This code has been written for the purposes of teaching
 *                  cryptography and computer security. It is to be used as
 *                  a demonstration only. No attempt has been made to optimise
 *                  the source code.
 * VERSION:         1.0-ICE
 *
 * REVISION HISTORY:
 *
 *****************************************************************************/

package StealthNet;

/* Import Libraries **********************************************************/

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/* StealthNetServer Class Definition *****************************************/

/**
 * A server process for StealthNet communications. Opens a server socket, 
 * listening on the specified listening port. For each incoming connection on 
 * this port, a new StealthNetServerThread is created. The 
 * StealthNetServerThread is responsible for communicating with that client.
 * 
 * The server is responsible for maintaining a list of users, as well as a list
 * of secrets. Whenever the server is sent a command, the server needs only to
 * pass some other command to the intended target client, enabling the two
 * clients to communicate with each other.
 * 
 * @author Matt Barrie 
 * @author Stephen Gould
 * @author Joshua Spence Added debug code and optional port number 
 * specification.
 */
public class StealthNetServer {
	/** 
	 * Use the argument `-Ddebug.StealthNetServer.XXX=true' at the command line
	 * to enable debug messages. Use the argument 
	 * `-Ddebug.StealthNetServer=true' to enable all debug messages. 
	 */
	private static final boolean DEBUG_GENERAL     = true && (System.getProperty("debug.StealthNetServer.General",    "false").equals("true") || System.getProperty("debug.StealthNetServer", "false").equals("true"));
	private static final boolean DEBUG_ERROR_TRACE = true && (System.getProperty("debug.StealthNetServer.ErrorTrace", "false").equals("true") || System.getProperty("debug.StealthNetServer", "false").equals("true") || System.getProperty("debug.ErrorTrace", "false").equals("true"));
	
	/** 
	 * The main StealthNetServer function.
	 * 
	 * @param args The command line arguments.
	 * @throws IOException
	 * 
	 * @author Matt Barrie 
     * @author Stephen Gould
	 * @author Joshua Spence Added debug code. Also modified code to accept an 
	 * optional port number parameter from the command line.
	 */
    public static void main(String[] args) throws IOException {
    	/** Port that the server is listening on. */
    	int port = StealthNetComms.DEFAULT_SERVERPORT;
    	
    	/** Check if a port number was specified at the command line. */
    	if (args.length > 0) {
    		try {
    			port = Integer.parseInt(args[0]);
    			
    			/** Check for a valid port number. */
    			if (port <= 0 || port > 65535)
    				throw new NumberFormatException("Invalid port number: " + port);
    		} catch (NumberFormatException e) {
    			System.err.println(e.getMessage());
    			if (DEBUG_ERROR_TRACE) e.printStackTrace();
                System.exit(1);
    		}
    	}
    	
    	/** Try to create a server socket listening on a specified port. */
        ServerSocket svrSocket = null;
        try {
            svrSocket = new ServerSocket(port);
        } catch (IOException e) {
            System.err.println("Could not listen on port: " + port);
            if (DEBUG_ERROR_TRACE) e.printStackTrace();
            System.exit(1);
        }

        if (DEBUG_GENERAL) System.out.println("Server is listening on port " + port + ".");
        System.out.println("Server online...");
        
        /** 
         * Wait for and accept connections on the server socket. Create a new 
         * thread for each connection.
         */
        while (true) {
        	Socket conn;
            new StealthNetServerThread(conn = svrSocket.accept()).start();
            
            if (DEBUG_GENERAL)
            	System.out.println("Server accepted connection from " + conn.getInetAddress() + " on port " + conn.getPort() + ".");
            else
            	System.out.println("Server accepted connection...");
        }
    }
}

/******************************************************************************
 * END OF FILE:     StealthNetServer.java
 *****************************************************************************/