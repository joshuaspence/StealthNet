/***********************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PROJECT:         StealthNet
 * FILENAME:        StealthNetComms.java
 * AUTHORS:         Stephen Gould, Matt Barrie, Ryan Junee
 * DESCRIPTION:     Implementation of StealthNet Communications for ELEC5616
 *                  programming assignment.
 *                  This code has been written for the purposes of teaching
 *                  cryptography and computer security. It is to be used as
 *                  a demonstration only. No attempt has been made to optimise
 *                  the source code.
 * VERSION:         1.0
 * IMPLEMENTS:      initiateSession();
 *                  acceptSession();
 *                  terminateSession();
 *                  sendPacket();
 *                  recvPacket();
 *                  recvReady();
 *
 * REVISION HISTORY:
 *
 **********************************************************************************/

package StealthNet;

/* Import Libraries **********************************************************/

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/* StealthNetComms class *****************************************************/

/**
 * A class to buffered write and buffered read to and from an opened socket.
 * 
 * @author Stephen Gould
 * @author Matt Barrie
 * @author Ryan Junee
 *
 */
public class StealthNetComms {
	/** 
	 * Use the argument `-Ddebug.StealthNetCommsXXX=true' at the command line
	 * to enable debug messages. Use the argument `-Ddebug.StealthNetComms=true'
	 * to enable all debug messages. 
	 */
	private static final boolean DEBUG_GENERAL          = true && (System.getProperty("debug.StealthNetComms.General",         "false").equals("true") || System.getProperty("debug.StealthNetComms", "false").equals("true"));
	private static final boolean DEBUG_ERROR_TRACE      = true && (System.getProperty("debug.StealthNetComms.ErrorTrace",      "false").equals("true") || System.getProperty("debug.StealthNetComms", "false").equals("true") || System.getProperty("debug.ErrorTrace", "false").equals("true"));
	private static final boolean DEBUG_RAW_PACKET       = true && (System.getProperty("debug.StealthNetComms.RawOutput",       "false").equals("true") || System.getProperty("debug.StealthNetComms", "false").equals("true"));
	private static final boolean DEBUG_DECODED_PACKET   = true && (System.getProperty("debug.StealthNetComms.DecodedOutput",   "false").equals("true") || System.getProperty("debug.StealthNetComms", "false").equals("true"));
	private static final boolean DEBUG_ENCRYPTED_PACKET = true && (System.getProperty("debug.StealthNetComms.EncryptedOutput", "false").equals("true") || System.getProperty("debug.StealthNetComms", "false").equals("true"));
	private static final boolean DEBUG_DECRYPTED_PACKET = true && (System.getProperty("debug.StealthNetComms.DecryptedOutput", "false").equals("true") || System.getProperty("debug.StealthNetComms", "false").equals("true"));
	private static final boolean DEBUG_RECEIVE_READY    = true && (System.getProperty("debug.StealthNetComms.ReceiveReady",    "false").equals("true") || System.getProperty("debug.StealthNetComms", "false").equals("true"));
	private static final boolean DEBUG_KEY_EXCHANGE     = true && (System.getProperty("debug.StealthNetComms.KeyExchange",     "false").equals("true") || System.getProperty("debug.StealthNetComms", "false").equals("true"));
	private static final boolean DEBUG_ENCRYPTION       = true && (System.getProperty("debug.StealthNetComms.Encryption",      "false").equals("true") || System.getProperty("debug.StealthNetComms", "false").equals("true"));
	
	/** Default host for the StealthNet server. */
    public static final String DEFAULT_SERVERNAME = "localhost";
    
    /** Default port for the StealthNet server. */
    public static final int DEFAULT_SERVERPORT = 5616;
    
    /** Current host - defaults to DFEAULT_SERVERNAME */
    public String servername;
    
    /** Current port - defaults to DEFAULT_SERVERPORT. */
    public int port;

    /** Opened socket through which the communication is to be made. */
    private Socket commsSocket;
    
    /** Provides authentication for the communication. */
    private StealthNetKeyExchange authenticationProvider;
    private SecretKey sharedSecretKey;
    
    /** Provides encryption and decryption for the communications. */
	private StealthNetEncryption confidentialityProvider;
    
    /** Provides integrity through creating checksums for messages. */
    @SuppressWarnings("unused")
	private static final StealthNetChecksum integrityProvider = new StealthNetChecksum();
    
    /** Prevents replay attacks using a PRNG. */
    @SuppressWarnings("unused")
    private StealthNetPRNG replayPrevention;

    /** Output data stream for the socket. */
    private PrintWriter dataOut;            
    
    /** Input data stream for the socket. */
    private BufferedReader dataIn;    
    
    /** Constructor. */
    public StealthNetComms() {
    	if (DEBUG_GENERAL) System.out.println("Creating StealthNetComms to " + DEFAULT_SERVERNAME + " on port " + DEFAULT_SERVERPORT + ".");
    	
    	commsSocket = null;
        dataIn = null;
        dataOut = null;
        
        servername = DEFAULT_SERVERNAME;
        port = DEFAULT_SERVERPORT;
    }
    
    /** 
     * Constructor. 
     * 
     * @param s The servername of the StealthNet server.
     * @param p The port number for the StealthNet server.
     */
    public StealthNetComms(String s, int p) {
    	if (DEBUG_GENERAL) System.out.println("Creating StealthNetComms to " + s + " on port " + p + ".");
    	
        commsSocket = null;
        dataIn = null;
        dataOut = null;
        
        servername = s;
        port = p;
    }

    /** 
     * Cleans up before terminating the class.
     * 
     * @throws IOException
     */
    protected void finalize() throws IOException {
        if (dataOut != null) dataOut.close();
        if (dataIn != null) dataIn.close();
        if (commsSocket != null) commsSocket.close();
    }

    /** 
     * Initiates a communications session. This occurs on the client side.
     * 
     * @param socket The socket through which the connection is made. 
     * @return True if the initialisation succeeds. False if the initialisation 
     * fails. 
     */
    public boolean initiateSession(Socket socket) {
    	if (DEBUG_GENERAL) System.out.println("Initiating StealthNetComms session.");
        try {
            commsSocket = socket;
            dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
            dataIn = new BufferedReader(new InputStreamReader(commsSocket.getInputStream()));
        } catch (Exception e) {
            System.err.println("Connection terminated.");
            if (DEBUG_ERROR_TRACE) e.printStackTrace();
            System.exit(1);
        }
        
        /** Perform Diffie-Hellman key exchange. */
        initKeyExchange();
        
        /** Wait for key exchange to finish. */
        /* TODO: probably want a timeout on this */
        if (DEBUG_GENERAL) System.out.println("Waiting for key exchange.");
        waitForKeyExchange();
        
        return true;
    }

    /** 
     * Accepts a connection on the given socket. This occurs on the server side.
     * 
     * @param socket The socket through which the connection is made. 
     * @return True if the initialisation succeeds. False if the initialisation 
     * fails. 
     */
    public boolean acceptSession(Socket socket) {
    	if (DEBUG_GENERAL) System.out.println("Accepting StealthNetComms session on port " + socket.getPort() + ".");
        try {
            commsSocket = socket;
            dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
            dataIn = new BufferedReader(new InputStreamReader(commsSocket.getInputStream()));
        } catch (Exception e) {
            System.err.println("Connection terminated.");
            if (DEBUG_ERROR_TRACE) e.printStackTrace();
            System.exit(1);
        }

        return true;
    }

    /**
     * Terminates the communication session and closes the socket, print writer 
     * and buffered reader associated with the communications.
     * 
     * @return True if the termination succeeds, otherwise false.
     */
    public boolean terminateSession() {
    	if (DEBUG_GENERAL) System.out.println("Terminating StealthNetComms session.");
        try {
            if (commsSocket == null)
                return false;
            dataIn.close();
            dataOut.close();
            commsSocket.close();
            commsSocket = null;
        } catch (Exception e) {
        	if (DEBUG_ERROR_TRACE) e.printStackTrace();
            return false;
        }

        return true;
    }

    /** 
     * Sends a command with no data.
     * 
     * @param command The command to be sent.
     * @return True if successful, otherwise false.
     */
    public boolean sendPacket(byte command) {
        return sendPacket(command, new byte[0]);
    }

    /**
     * Sends a command and data.
     * 
     * @param command The command to be sent.
     * @param data The data to be sent.
     * @return True if successful, otherwise false.
     */
    public boolean sendPacket(byte command, String data) {
        return sendPacket(command, data.getBytes());
    }

    /**
     * Sends a command and data.
     * 
     * @param command The command to be sent.
     * @param data The data to be sent.
     * @return True if successful, otherwise false.
     */
    public boolean sendPacket(byte command, byte[] data) {
        return sendPacket(command, data, data.length);
    }

    /**
     * Sends a command and data.
     * 
     * @param command The command to be sent.
     * @param data The data to be sent.
     * @param size The size of the data field.
     * @return True if successful, otherwise false.
     */
    public boolean sendPacket(byte command, byte[] data, int size) {
        final StealthNetPacket pckt = new StealthNetPacket();
        pckt.command = command;
        pckt.data = new byte[size];
        System.arraycopy(data, 0, pckt.data, 0, size);
        return sendPacket(pckt);
    }

    /**
     * Sends a StealthNet packet by writing it to the print writer for the 
     * socket.
     * 
     * @param pckt The packet to be sent.
     * @return True if successful, otherwise false.
     */
    public boolean sendPacket(StealthNetPacket pckt) {
    	/** 
    	 * We shouldn't send any packets unless we have performed authentication
    	 * using the Diffie-Hellman key exchange.
    	 */
    	if ((sharedSecretKey == null) && (pckt.command != StealthNetPacket.CMD_PUBLICKEY)) {
    		System.err.println("Cannot send non-authentication packets until parties have exchanged authentication keys.");
    		return false;
    	}
    	
    	if (DEBUG_RAW_PACKET)     System.out.println("(raw)       sendPacket(" + pckt.toString() + ")");
    	if (DEBUG_DECODED_PACKET) {
    		if (pckt.data.length <= 0)
    			System.out.println("(decoded)   sendPacket(" + StealthNetPacket.getCommandName(pckt.command) + ")");
    		else
    			System.out.println("(decoded)   sendPacket(" + StealthNetPacket.getCommandName(pckt.command) + ", " + (new String(pckt.data)).replaceAll("\n", ";") + ")");
    	}
    	
    	String packetString = pckt.toString();
    	if (confidentialityProvider != null) {
    		try {
				packetString = confidentialityProvider.encrypt(pckt.toString());
			} catch (Exception e) {
				System.err.println("Failed to encrypt packet.");
				if (DEBUG_ERROR_TRACE) e.printStackTrace();
				System.exit(1);
			}
    		
    		if (DEBUG_ENCRYPTED_PACKET)	System.out.println("(encrypted) sendPacket(" + packetString + ")");
    	}
    	
        if (dataOut == null)
            return false;
        
        /** Print the packet to the output writer. */
        dataOut.println(packetString);
        return true;
    }

    /**
     * Reads a StealthNet packet from the buffered reader for the socket.
     * 
     * @return The packet that was received.
     */
    public StealthNetPacket recvPacket() throws IOException {
        StealthNetPacket pckt = null;
        
        /** Read data from the input buffer. */
        final String str = dataIn.readLine();
        
        /** Convert the data to a packet. */
        if (str == null)
        	return null;
        
        String packetString = str;
        
        /** Attempt to decrypt the packet. */
    	if (confidentialityProvider != null) {
    		try {
				packetString = confidentialityProvider.decrypt(str);
			} catch (Exception e) {
				System.err.println("Failed to decrypt packet.");
				if (DEBUG_ERROR_TRACE) e.printStackTrace();
				System.exit(1);
			}
    		
    		if (DEBUG_DECRYPTED_PACKET)	System.out.println("(decrypted) sendPacket(" + packetString + ")");
    	} else {
    		if (DEBUG_DECRYPTED_PACKET)	System.out.println("Packet is not encrypted.");
    	}
    	
    	// Check the integrity of the message.
    	
    	pckt = new StealthNetPacket(packetString);
        
        if (DEBUG_RAW_PACKET)     System.out.println("(raw)     recvPacket(" + packetString + ")");
        if (DEBUG_DECODED_PACKET) {
        	if (pckt.data.length <= 0)
        		System.out.println("(decoded) recvPacket(" + StealthNetPacket.getCommandName(pckt.command) + ")");
        	else
        		System.out.println("(decoded) recvPacket(" + StealthNetPacket.getCommandName(pckt.command) + ", " + (new String(pckt.data)).replaceAll("\n", ";") + ")");
        }
        
        return pckt;
    }

    // Just to limit the verbosity of output in recvReady
 	// {
     private boolean prev_isconnected = false;
     private boolean prev_isclosed = false;
     private boolean prev_isinputshutdown = false;
     private boolean prev_isoutputshutdown = false;
     private boolean is_first_time = true;
     // }
    
    /**
     * Checks if the class is ready to receive more data.  
     * 
     * @return True to indicate ready-to-receive. False to indicate not-ready.
     * @throws IOException
     */
    public boolean recvReady() throws IOException {
    	// Just to limit the verbosity of output
    	// {
    	final boolean isconnected = commsSocket.isConnected();
    	final boolean isclosed = commsSocket.isClosed();
    	final boolean isinputshutdown = commsSocket.isInputShutdown();
    	final boolean isoutputshutdown = commsSocket.isOutputShutdown();
    	
    	if (DEBUG_RECEIVE_READY && (is_first_time || (prev_isconnected != isconnected || prev_isclosed != isclosed || prev_isinputshutdown != isinputshutdown || prev_isoutputshutdown != isoutputshutdown))) {
	        System.out.println("Connected: " + isconnected);
	        System.out.println("Closed: " + isclosed);
	        System.out.println("InClosed: " + isinputshutdown);
	        System.out.println("OutClosed: " + isoutputshutdown);
	        
	        prev_isconnected = isconnected;
	        prev_isclosed = isclosed;
	        prev_isinputshutdown = isinputshutdown;
	        prev_isoutputshutdown = isoutputshutdown;
    	}
    	
    	is_first_time = false;
    	// }
    	
        return dataIn.ready();
    }
    
    /** 
     * Perform a Diffie-Hellman key exchange with the other party.
     * @see StealthNetKeyExchange 
     */
    public void initKeyExchange() {
    	if (DEBUG_KEY_EXCHANGE) System.out.println("Initiating Diffie-Hellman key exchange.");
    	
    	if (authenticationProvider != null) {
    		System.out.println("Key exchange has already been initialised.");
    		return;
    	}
    	
    	try {
			authenticationProvider = new StealthNetKeyExchange(StealthNetKeyExchange.NUM_BITS, new SecureRandom());
		} catch (Exception e) {
			System.err.println("Unable to authenticated.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			System.exit(1);
		}
    	
    	/** Transmit our public key. */
    	String pubKey = authenticationProvider.getPublicKey().toString();
    	if (DEBUG_KEY_EXCHANGE) System.out.println("Sending public key: " + pubKey);
    	sendPacket(StealthNetPacket.CMD_PUBLICKEY, pubKey);
    }
    
    /**
     * Continuously receives (and discards) packets until the Diffie-Hellman
     * key exchange has completed.
     */
    private void waitForKeyExchange() {
    	while (sharedSecretKey == null) {
    		try {
	        	StealthNetPacket pckt;
					pckt = recvPacket();
	            
	            switch (pckt.command) {
	            	case StealthNetPacket.CMD_PUBLICKEY:
	            		final String pubKey = new String(pckt.data);
	                	if (DEBUG_ENCRYPTION) System.out.println("Received a public key command. Key: \"" + pubKey + "\".");
	                	
	                	if (DEBUG_GENERAL) System.out.println("Performing key exchange.");
	            	    keyExchange(pubKey);
	                    break;
	            
	                default:
	                    System.err.println("Unexpected command received from server.");
	            }
    		}  catch (IOException e) {}
        }
    }
    
    /** 
     * Perform a Diffie-Hellman key exchange with the other party.
     * @param publicKey The public key that was sent to us.
     * @see StealthNetKeyExchange 
     */
    public void keyExchange(String publicKey) {
    	if (DEBUG_KEY_EXCHANGE) System.out.println("Received public key: " + publicKey);
    	
    	if (authenticationProvider == null) {
    		/** We haven't yet made our own private/public keys. */
    		initKeyExchange();
    	}
    	
    	/** Generate the shared key. */
    	if (DEBUG_KEY_EXCHANGE) System.out.println("Generating the shared secret key.");
		try {
			sharedSecretKey = authenticationProvider.getSharedSecret(new BigInteger(publicKey));
			if (DEBUG_KEY_EXCHANGE) System.out.println("Generated shared secret key: " + new String(getHexValue(sharedSecretKey.getEncoded())));
		} catch (Exception e) {
			System.err.println("Unable to authenticate. Failed to generate shared secret key.");
			if (DEBUG_KEY_EXCHANGE) e.printStackTrace();
			System.exit(1);
		}
		
		try {
			/** Use a hash shared secret key for encryption and decryption. */
			MessageDigest mdb = MessageDigest.getInstance(StealthNetEncryption.HASH_ALGORITHM);
			
			SecretKey cryptKey = new SecretKeySpec(mdb.digest(sharedSecretKey.getEncoded()), StealthNetEncryption.KEY_ALGORITHM);
			if (DEBUG_ENCRYPTION) System.out.println("Generated encryption/decryption key: " + new String(getHexValue(cryptKey.getEncoded())));
			
			confidentialityProvider = new StealthNetEncryption(cryptKey, cryptKey);
		} catch (Exception e) {
			System.err.println("Unable to provide encryption/decrypted. Failed to initialise encryption class.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			System.exit(1);
		}
    }
    
    /**
     * Function to assist with printing cryptographic keys by returning byte 
     * arrays as a hexadecimal number.
     * 
     * @param array The byte array to transfer into a hexadecimal number.
     * @return The string containing the hexadecimal number.
     */
    private static char[] getHexValue(byte[] array) {
        final char[] symbols="0123456789ABCDEF".toCharArray();
        char[] hexValue = new char[array.length * 2];
	 
        for (int i = 0; i < array.length; i++) {
        	/** Convert the byte to an int. */
	        int current = array[i] & 0xff;
		
	        /** Determine the Hex symbol for the last 4 bits. */
	        hexValue[i * 2 + 1] = symbols[current & 0x0f];
		
	        /** Determine the Hex symbol for the first 4 bits */
	        hexValue[i * 2] = symbols[current >> 4];
        }
	     
        return hexValue;
    }
}

/******************************************************************************
 * END OF FILE:     StealthNetComms.java
 *****************************************************************************/