/* @formatter:off */
/******************************************************************************
 *
 * ELEC5616/NETS3016
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet
 * FILENAME:        Bank.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     Implementation of StealthNet Bank (FirstVirtual) for
 * 					ELEC5616/NETS3016 programming assignment.
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

/* StealthNet.Bank Class Definition **************************************** */

/**
 * A bank for the StealthNet communications system. Opens a {@link ServerSocket}
 * , listening on the specified listening port. For each incoming connection on
 * this port, a new {@link BankThread} is created. The {@link BankThread} class
 * is responsible for communicating with that peer (either a {@link Client} or a
 * {@link Server}) for the purposes of signing and verifying payments.
 * 
 * The bank is responsible for maintaining account information (such as current
 * account balances) for all logged in users. The bank is responsible for
 * signing {@link CryptoCreditHashChain}s belonging to a {@link Client} so that
 * the {@link Server} can verify the validity of the purchase.
 * 
 * @author Joshua Spence
 * @see BankThread
 */
public class Bank {
	/* Debug options. */
	private static final boolean DEBUG_GENERAL = Debug.isDebug("StealthNet.Bank.General");
	private static final boolean DEBUG_ERROR_TRACE = Debug.isDebug("StealthNet.Bank.ErrorTrace") || Debug.isDebug("ErrorTrace");
	
	/* Use the BouncyCastle API. */
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	/**
	 * The main Bank function.
	 * 
	 * @param args The command line arguments. The command lines arguments take
	 *        the following format. <ul> <li> <code>args[0]</code> ::=
	 *        <code>port</code> </li> </ul>
	 * @throws IOException
	 */
	public static void main(final String[] args) throws IOException {
		/* Port that the bank is listening on. */
		int port = Comms.DEFAULT_BANKPORT;
		
		/* Check if a port number was specified at the command line. */
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
		
		/* Try to create a server socket listening on a specified port. */
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
		
		/*
		 * Wait for and accept connections on the server socket. Create a new
		 * thread for each connection.
		 */
		while (true)
			try {
				final Socket conn = svrSocket.accept();
				final BankThread thread = new BankThread(conn);
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
