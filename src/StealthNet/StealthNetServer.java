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

/* StealthNetServer Class Definition *****************************************/

/**
 * A server process for StealthNet communications. Opens a server socket, 
 * listening on the specified listening port. For each incoming connection on 
 * this port, a new StealthNetServerThread is created.
 * 
 * @author Matt Barrie 
 * @author Stephen Gould
 */
public class StealthNetServer {
	/** Set to true in build.xml to output debug messages for this class. */
	private static final boolean DEBUG = System.getProperty("debug." + StealthNetServer.class.getName(), "false").equals("true");
	
	/** 
	 * The main StealthNetServer function.
	 * 
	 * @param args The command line arguments.
	 * @throws IOException
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
    			if (DEBUG) e.printStackTrace();
                System.exit(1);
    		}
    	}
    	
    	/** Try to create a server socket listening on a specified port. */
        ServerSocket svrSocket = null;
        try {
            svrSocket = new ServerSocket(port);
        } catch (IOException e) {
            System.err.println("Could not listen on port: " + port);
            if (DEBUG) e.printStackTrace();
            System.exit(1);
        }

        System.out.println("Server listening on port " + port + ".");
        System.out.println("Server online...");
        
        /** 
         * Wait for and accept connections on the server socket. Create a new 
         * thread for each connection.
         */
        while (true) {
            new StealthNetServerThread(svrSocket.accept()).start();
            System.out.println("Server accepted connection...");
        }
    }
}

/******************************************************************************
 * END OF FILE:     StealthNetServer.java
 *****************************************************************************/