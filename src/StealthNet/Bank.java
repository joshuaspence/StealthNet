/* @formatter:off */
/******************************************************************************
 *
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
/* @formatter:on */

package StealthNet;

/* Import Libraries ******************************************************** */

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;

import StealthNet.Security.AsymmetricEncryption;
import StealthNet.Security.RSAAsymmetricEncryption;

/* StealthNet.Bank Class Definition **************************************** */

/**
 * TODO
 * 
 * @author Joshua Spence
 */
public class Bank {
	/** Debug options. */
	private static final boolean DEBUG_GENERAL = Debug.isDebug("StealthNet.Bank.General");
	private static final boolean DEBUG_ERROR_TRACE = Debug.isDebug("StealthNet.Bank.ErrorTrace") || Debug.isDebug("ErrorTrace");
	private static final boolean DEBUG_ASYMMETRIC_ENCRYPTION = Debug.isDebug("StealthNet.Bank.AsymmetricEncryption");
	
	/** Constants. */
	private static final String PUBLIC_KEY_FILE = "keys/bank/public.key";
	private static final String PRIVATE_KEY_FILE = "keys/bank/private.key";
	private static final String PRIVATE_KEY_FILE_PASSWORD = "bank";
	
	/**
	 * The main Bank function.
	 * 
	 * @param args The command line arguments.
	 * @throws IOException
	 */
	public static void main(final String[] args) throws IOException {
		/**
		 * Try to read keys from the JAR file first. If that doesn't work, then
		 * try to read keys from the file system. If that doesn't work, then
		 * create new keys.
		 */
		KeyPair bankKeys = null;
		try {
			bankKeys = Utility.getPublicPrivateKeys(PUBLIC_KEY_FILE, PRIVATE_KEY_FILE, PRIVATE_KEY_FILE_PASSWORD);
		} catch (final Exception e) {
			System.err.println("Unable to retrieve/generate public/private keys.");
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
			System.exit(1);
		}
		if (bankKeys == null) {
			System.err.println("Unable to retrieve/generate public-private keys.");
			System.exit(1);
		}
		
		/** Debug information. */
		if (DEBUG_ASYMMETRIC_ENCRYPTION) {
			final String publicKeyString = Utility.getHexValue(bankKeys.getPublic().getEncoded());
			final String privateKeyString = Utility.getHexValue(bankKeys.getPrivate().getEncoded());
			System.out.println("Public key: " + publicKeyString);
			System.out.println("Private key: " + privateKeyString);
		}
		
		/** Port that the bank is listening on. */
		int port = Comms.DEFAULT_BANKPORT;
		
		/** Check if a port number was specified at the command line. */
		if (args.length > 0)
			try {
				port = Integer.parseInt(args[0]);
				
				/** Check for a valid port number. */
				if (port <= 0 || port > 65535)
					throw new NumberFormatException("Invalid port number: " + port);
			} catch (final NumberFormatException e) {
				System.err.println(e.getMessage());
				if (DEBUG_ERROR_TRACE)
					e.printStackTrace();
				System.exit(1);
			}
		
		/** Try to create a server socket listening on a specified port. */
		ServerSocket svrSocket = null;
		try {
			svrSocket = new ServerSocket(port);
		} catch (final IOException e) {
			System.err.println("Could not listen on port " + port);
			if (DEBUG_ERROR_TRACE)
				e.printStackTrace();
			System.exit(1);
		}
		
		if (DEBUG_GENERAL)
			System.out.println("Bank is listening on port " + port + ".");
		System.out.println("Bank online...");
		
		/**
		 * Wait for and accept connections on the server socket. Create a new
		 * thread for each connection.
		 */
		while (true)
			try {
				final Socket conn = svrSocket.accept();
				final AsymmetricEncryption ae = new RSAAsymmetricEncryption(bankKeys);
				final BankThread thread = new BankThread(conn, ae);
				thread.start();
				
				if (DEBUG_GENERAL)
					System.out.println("Bank accepted connection from " + conn.getInetAddress() + " on port " + conn.getPort() + ".");
				else
					System.out.println("Bank accepted connection...");
			} catch (final Exception e) {
				System.err.println("Error accepting new connection. Dropping connection...");
				if (DEBUG_ERROR_TRACE)
					e.printStackTrace();
			}
	}
}

/******************************************************************************
 * END OF FILE: Bank.java
 *****************************************************************************/
