/******************************************************************************
 * ELEC5616/NETS3016
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet
 * FILENAME:        Bank.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     Implementation of StealthNet bank (FirstVirtual) for 
 * 					ELEC5616/NETS3016 programming assignment.
 *
 *****************************************************************************/

package StealthNet;

/* Import Libraries **********************************************************/

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;

import StealthNet.Security.RSAAsymmetricEncryption;

/* StealthNet.Bank Class Definition ******************************************/

/**
 * TODO
 * 
 * @author Joshua Spence
 */
public class Bank {
	/** Debug options. */
	private static final boolean DEBUG_GENERAL               = Debug.isDebug("StealthNet.Bank.General");
	private static final boolean DEBUG_ERROR_TRACE           = Debug.isDebug("StealthNet.Bank.ErrorTrace") || Debug.isDebug("ErrorTrace");
	private static final boolean DEBUG_ASYMMETRIC_ENCRYPTION = Debug.isDebug("StealthNet.Bank.AsymmetricEncryption");
	
	/** Constants. */
	private static final String PUBLIC_KEY_FILE = "keys/bank/public.key";
	private static final String PRIVATE_KEY_FILE = "keys/bank/private.key";
	
	/** 
	 * The main Bank function.
	 * 
	 * @param args The command line arguments.
	 * @throws IOException
	 */
    public static void main(String[] args) throws IOException {
    	final URL publicKeyFile = Bank.class.getClassLoader().getResource(PUBLIC_KEY_FILE);
    	final URL privateKeyFile = Bank.class.getClassLoader().getResource(PRIVATE_KEY_FILE);
    	
    	RSAAsymmetricEncryption asymmetricEncryptionProvider = null;
    	try {
    		if ((publicKeyFile == null) || (privateKeyFile == null)) {
    			/** Create new public/private keys. */
        		asymmetricEncryptionProvider = new RSAAsymmetricEncryption();
        		if (DEBUG_ASYMMETRIC_ENCRYPTION) System.out.println("Created new public/private keys.");
        		asymmetricEncryptionProvider.savePublicKeyToFile(PUBLIC_KEY_FILE);
        		asymmetricEncryptionProvider.savePrivateKeyToFile(PRIVATE_KEY_FILE);
        	} else {
        		/** Read public/private keys from file. */
	    		asymmetricEncryptionProvider = new RSAAsymmetricEncryption(publicKeyFile, privateKeyFile);
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
    	
    	/** Port that the bank is listening on. */
    	int port = Comms.DEFAULT_BANKPORT;
    	
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

        if (DEBUG_GENERAL) System.out.println("Bank is listening on port " + port + ".");
        System.out.println("Bank online...");
        
        /** 
         * Wait for and accept connections on the server socket. Create a new 
         * thread for each connection.
         */
        while (true) {
        	final Socket conn = svrSocket.accept();
        	final BankThread thread = new BankThread(conn);
        	thread.start();
            
            if (DEBUG_GENERAL)
            	System.out.println("Bank accepted connection from " + conn.getInetAddress() + " on port " + conn.getPort() + ".");
            else
            	System.out.println("Bank accepted connection...");
        }
    }
}

/******************************************************************************
 * END OF FILE:     Bank.java
 *****************************************************************************/