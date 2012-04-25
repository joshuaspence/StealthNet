/******************************************************************************
 * ELEC5616/NETS3016
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie and Stephen Gould
 *
 * PACKAGE:         StealthNet
 * FILENAME:        Server.java
 * AUTHORS:         Matt Barrie, Stephen Gould and Joshua Spence
 * DESCRIPTION:     Implementation of StealthNet Server for ELEC5616/NETS3016
 *                  programming assignment.
 *
 *****************************************************************************/

package StealthNet;

/* Import Libraries **********************************************************/

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;

import StealthNet.Security.AsymmetricEncryption;
import StealthNet.Security.RSAAsymmetricEncryption;

/* StealthNet.Server Class Definition ****************************************/

/**
 * A server process for StealthNet communications. Opens a server socket, 
 * listening on the specified listening port. For each incoming connection on 
 * this port, a new ServerThread is created. The ServerThread class is 
 * responsible for communicating with that client.
 * 
 * The server is responsible for maintaining a list of users, as well as a list
 * of secrets. Whenever the server is sent a command, the server needs only to
 * pass some other command to the intended target client, enabling the two
 * clients to communicate with each other.
 * 
 * @author Matt Barrie 
 * @author Stephen Gould
 * @author Joshua Spence
 */
public class Server {
	/** Debug options. */
	private static final boolean DEBUG_GENERAL               = Debug.isDebug("StealthNet.Server.General");
	private static final boolean DEBUG_ERROR_TRACE           = Debug.isDebug("StealthNet.Server.ErrorTrace") || Debug.isDebug("ErrorTrace");
	private static final boolean DEBUG_ASYMMETRIC_ENCRYPTION = Debug.isDebug("StealthNet.Server.AsymmetricEncryption");
	
	/** Constants. */
	private static final String PUBLIC_KEY_FILE = "keys/server/public.key";
	private static final String PRIVATE_KEY_FILE = "keys/server/private.key";
	
	/** 
	 * The main Server function.
	 * 
	 * @param args The command line arguments.
	 * @throws IOException
	 */
    public static void main(String[] args) throws IOException {
    	final URL publicKeyFile = Server.class.getClassLoader().getResource(PUBLIC_KEY_FILE);
    	final URL privateKeyFile = Server.class.getClassLoader().getResource(PRIVATE_KEY_FILE);
    	
    	AsymmetricEncryption asymmetricEncryptionProvider = null;
    	try {
    		if ((publicKeyFile == null) || (privateKeyFile == null)) {
    			/** Create new public/private keys. */
        		asymmetricEncryptionProvider = new RSAAsymmetricEncryption(null);
        		if (DEBUG_ASYMMETRIC_ENCRYPTION) System.out.println("Created new public/private keys.");
        		asymmetricEncryptionProvider.savePublicKeyToFile(PUBLIC_KEY_FILE);
        		asymmetricEncryptionProvider.savePrivateKeyToFile(PRIVATE_KEY_FILE);
        	} else {
        		/** Read public/private keys from file. */
	    		asymmetricEncryptionProvider = new RSAAsymmetricEncryption(publicKeyFile, privateKeyFile, null);
				if (DEBUG_ASYMMETRIC_ENCRYPTION) System.out.println("Read public/private keys from file.");
        	}
		} catch (Exception e) {
			System.err.println(e.getMessage());
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			System.exit(1);
		}
    	
    	/** Debug information. */
    	final String publicKeyString = new String(Utility.getHexValue(asymmetricEncryptionProvider.getPublicKey().getEncoded()));
    	final String privateKeyString = new String(Utility.getHexValue(asymmetricEncryptionProvider.getPrivateKey().getEncoded()));
    	if (DEBUG_ASYMMETRIC_ENCRYPTION) System.out.println("Public key: " + publicKeyString);
		if (DEBUG_ASYMMETRIC_ENCRYPTION) System.out.println("Private key: " + privateKeyString);
    	
    	/** Port that the server is listening on. */
    	int port = Comms.DEFAULT_SERVERPORT;
    	
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
            System.err.println("Could not listen on port " + port);
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
        	final Socket conn = svrSocket.accept();
        	final ServerThread thread = new ServerThread(conn, asymmetricEncryptionProvider);
        	thread.start();
            
            if (DEBUG_GENERAL)
            	System.out.println("Server accepted connection from " + conn.getInetAddress() + " on port " + conn.getPort() + ".");
            else
            	System.out.println("Server accepted connection...");
        }
    }
}

/******************************************************************************
 * END OF FILE:     Server.java
 *****************************************************************************/