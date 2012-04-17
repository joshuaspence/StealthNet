/***********************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet
 * FILENAME:        Comms.java
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

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import StealthNet.Security.AESEncryption;
import StealthNet.Security.DiffieHellmanKeyExchange;
import StealthNet.Security.EncryptionHandler;
import StealthNet.Security.HashedMessageAuthenticationCode;
import StealthNet.Security.KeyExchange;
import StealthNet.Security.MessageAuthenticationCode;
import StealthNet.Security.TokenGenerator;

/* Comms class ***************************************************************/

/**
 * A class to buffered write and buffered read to and from an opened socket.
 * 
 * @author Stephen Gould
 * @author Matt Barrie
 * @author Ryan Junee
 * @author Joshua Spence (Implemented security-related functionality. Also added
 * debug code). 
 *
 */
public class Comms {
	/** Debug options. */
	private static final boolean DEBUG_GENERAL          = Debug.isDebug("StealthNet.Comms.General");
	private static final boolean DEBUG_ERROR_TRACE      = Debug.isDebug("StealthNet.Comms.ErrorTrace") || Debug.isDebug("ErrorTrace");
	private static final boolean DEBUG_RAW_PACKET       = Debug.isDebug("StealthNet.Comms.RawOutput");
	private static final boolean DEBUG_DECODED_PACKET   = Debug.isDebug("StealthNet.Comms.DecodedOutput");
	private static final boolean DEBUG_ENCRYPTED_PACKET = Debug.isDebug("StealthNet.Comms.EncryptedOutput");
	private static final boolean DEBUG_DECRYPTED_PACKET = Debug.isDebug("StealthNet.Comms.DecryptedOutput");
	private static final boolean DEBUG_RECEIVE_READY    = Debug.isDebug("StealthNet.Comms.ReceiveReady");
	private static final boolean DEBUG_KEY_EXCHANGE     = Debug.isDebug("StealthNet.Comms.KeyExchange");
	private static final boolean DEBUG_ENCRYPTION       = Debug.isDebug("StealthNet.Comms.Encryption");
	private static final boolean DEBUG_INTEGRITY        = Debug.isDebug("StealthNet.Comms.Integrity");
	
	/** Defaults. */
    public static final String DEFAULT_SERVERNAME = "localhost";	/** Default host for the StealthNet server. */
    public static final int DEFAULT_SERVERPORT = 5616;				/** Default port for the StealthNet server. */
    public static final int DEFAULT_PROXYPORT = 5617;				/** Default port for the StealthNet proxy. */
    
    /** Current values. */
    private final String servername;	/** This host - defaults to DFEAULT_SERVERNAME */
    private final int port;				/** This port - defaults to DEFAULT_SERVERPORT. */

    /** Opened socket through which the communication is to be made. */
    private Socket commsSocket;
    
    /** Provides authentication for the communication. */
	private final static int KEY_EXCHANGE_NUM_BITS = 1024;
    private KeyExchange authenticationProvider = null;
    private SecretKey sharedSecretKey = null;
    
    /** Provides encryption and decryption for the communications. */
	private EncryptionHandler confidentialityProvider = null;
    
    /** Provides integrity through creating checksums for messages. */
	private MessageAuthenticationCode integrityProvider = null;
    
    /** Prevents replay attacks using a PRNG. */
	private TokenGenerator replayPrevention;

    /** Output data stream for the socket. */
    private PrintWriter dataOut;            
    
    /** Input data stream for the socket. */
    private BufferedReader dataIn;
    
    /** Disable all security measures. Should be used with caution. */
    private final boolean disableSecurity;
    
    /** Constructor. */
    public Comms() {
    	this.commsSocket = null;
    	this.dataIn = null;
    	this.dataOut = null;
        
        this.servername = DEFAULT_SERVERNAME;
        this.port = DEFAULT_SERVERPORT;
        
        this.disableSecurity = false;
        
        if (this.disableSecurity)
        	if (DEBUG_GENERAL) System.out.println("Creating insecure StealthNet.Comms to " + this.servername + " on port " + this.port + ".");
    	else
    		if (DEBUG_GENERAL) System.out.println("Creating secure StealthNet.Comms to " + this.servername + " on port " + this.port + ".");
    }
    
    /** 
     * Constructor.
     * 
     * @param disableSecurity Disable all security measures.
     */
    public Comms(boolean disableSecurity) {
    	this.commsSocket = null;
    	this.dataIn = null;
    	this.dataOut = null;
        
        this.servername = DEFAULT_SERVERNAME;
        this.port = DEFAULT_SERVERPORT;
        
        this.disableSecurity = disableSecurity;
        
        if (this.disableSecurity)
        	if (DEBUG_GENERAL) System.out.println("Creating insecure StealthNet.Comms to " + this.servername + " on port " + this.port + ".");
    	else
    		if (DEBUG_GENERAL) System.out.println("Creating secure StealthNet.Comms to " + this.servername + " on port " + this.port + ".");
    }
    
    /** 
     * Constructor. 
     * 
     * @param s The servername of the StealthNet server.
     * @param p The port number for the StealthNet server.
     * @param disableSecurity Disable all security measures.
     */
    public Comms(String s, int p, boolean disableSecurity) {    	
    	this.commsSocket = null;
        this.dataIn = null;
        this.dataOut = null;
        
        this.servername = s;
        this.port = p;
        
        this.disableSecurity = disableSecurity;
        
        if (this.disableSecurity)
        	if (DEBUG_GENERAL) System.out.println("Creating insecure StealthNet.Comms to " + this.servername + " on port " + this.port + ".");
    	else
    		if (DEBUG_GENERAL) System.out.println("Creating secure StealthNet.Comms to " + this.servername + " on port " + this.port + ".");
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
     * Initiates a communications session. This occurs on the client side. The
     * peer that initiates the session is also responsible for initiating the 
     * key exchange, as well as sharing the MAC key.
     * 
     * @param socket The socket through which the connection is made. 
     * @return True if the initialisation succeeds. False if the initialisation 
     * fails. 
     */
    public boolean initiateSession(Socket socket) {
    	if (DEBUG_GENERAL) System.out.println("Initiating StealthNet.Comms session.");
        try {
            commsSocket = socket;
            dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
            dataIn = new BufferedReader(new InputStreamReader(commsSocket.getInputStream()));
        } catch (Exception e) {
            System.err.println("Connection terminated!");
            if (DEBUG_ERROR_TRACE) e.printStackTrace();
            return false;
        }
        
        if (!disableSecurity) {
	        /** Perform key exchange. */
	        initKeyExchange();
	        
	        /** 
	         * Wait for key exchange to finish. 
	         * @todo Possibly want a timeout on this.
	         */
	        waitForKeyExchange();
	        
	        /** 
	         * Generate and transmit MAC key. Then wait for the peer to send an 
	         * acknowledgement.
	         */
	        doIntegrityKey();
        }
        
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
    	if (DEBUG_GENERAL) System.out.println("Accepting StealthNet.Comms session on port " + socket.getPort() + ".");
        try {
            commsSocket = socket;
            dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
            dataIn = new BufferedReader(new InputStreamReader(commsSocket.getInputStream()));
        } catch (Exception e) {
            System.err.println("Connection terminated!");
            if (DEBUG_ERROR_TRACE) e.printStackTrace();
            System.exit(1);
        }
        
        /** TODO: maybe put some code here to wait for security stuff? */

        return true;
    }

    /**
     * Terminates the communication session and closes the socket, print writer 
     * and buffered reader associated with the communications.
     * 
     * @return True if the termination succeeds, otherwise false.
     */
    public boolean terminateSession() {
    	if (DEBUG_GENERAL) System.out.println("Terminating StealthNet.Comms session.");
        try {
            if (commsSocket == null)
                return false;
            dataIn.close();
            dataOut.close();
            commsSocket.close();
            commsSocket = null;
        } catch (Exception e) {
        	System.err.println("Error occurred while terminating session!");
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
     * @param dataSize The size of the data field.
     * @return True if successful, otherwise false.
     */
    public boolean sendPacket(byte command, byte[] data, int dataSize) {
        final Packet pckt = new Packet(command, data, dataSize, integrityProvider, null);
        return sendPacket(pckt);
    }

    /**
     * Sends a StealthNet packet by writing it to the print writer for the 
     * socket. Before transmitting the packet, the packet is encrypted. If 
     * packet encryption cannot be performed yet (because 
     * confidentialityProvider is null, then an unencrypted packet will be sent.
     * Beware that this may not always be what is wanted.
     * 
     * @param pckt The packet to be sent.
     * @return True if successful, otherwise false.
     */
    public boolean sendPacket(Packet pckt) {    	
    	/** Print debug information. */
    	if (DEBUG_RAW_PACKET)     System.out.println("(raw)       sendPacket(" + pckt.toString() + ")");
    	if (DEBUG_DECODED_PACKET) {
    		if (pckt.data.length <= 0) {
    			if (pckt.digest.length <= 0)
    				System.out.println("(decoded)   sendPacket(" + Packet.getCommandName(pckt.command) + ", null, null)");
    			else
    				System.out.println("(decoded)   sendPacket(" + Packet.getCommandName(pckt.command) + ", null, " + (new String(pckt.digest)) + ")");
    		} else {
    			if (pckt.digest.length <= 0)
    				System.out.println("(decoded)   sendPacket(" + Packet.getCommandName(pckt.command) + ", " + (new String(pckt.data)).replaceAll("\n", ";") + ", null)");
    			else
    				System.out.println("(decoded)   sendPacket(" + Packet.getCommandName(pckt.command) + ", " + (new String(pckt.data)).replaceAll("\n", ";") + ", " + (new String(pckt.digest)) + ")");
    		}
    	}
    	
    	/** Attempt to encrypt the packet. */
    	String packetString = pckt.toString();
    	if (confidentialityProvider != null) {
    		try {
				packetString = confidentialityProvider.encrypt(pckt.toString());
			} catch (Exception e) {
				System.err.println("Failed to encrypt packet!");
				if (DEBUG_ERROR_TRACE) e.printStackTrace();
				return false;
			}
    		if (DEBUG_ENCRYPTED_PACKET)	System.out.println("(encrypted) sendPacket(" + packetString + ")");
    	}
    	
        if (dataOut == null) {
        	System.err.println("PrintWriter does not exist!");
            return false;
        }
        
        /** Print the packet to the output writer. */
        dataOut.println(packetString);
        return true;
    }

    /**
     * Reads a StealthNet packet from the buffered reader for the socket. If the
     * packet is a special command (authentication key, integrity key, etc.) 
     * then this function handles that packet and does not return it to the 
     * user (instead, it will return null).
     * 
     * @return The packet that was received.
     */
    public Packet recvPacket() throws IOException {
        Packet pckt = null;
        
        /** Read data from the input buffer. */
        final String str = dataIn.readLine();
        
        if (str == null)
        	return null;
        
        /** Attempt to decrypt the packet. */
        String packetString = str;
    	if (confidentialityProvider != null) {
    		try {
				packetString = confidentialityProvider.decrypt(str);
			} catch (Exception e) {
				System.err.println("Failed to decrypt packet! Discarding...");
				if (DEBUG_ERROR_TRACE) e.printStackTrace();
				return null;
			}
    		if (DEBUG_DECRYPTED_PACKET)	System.out.println("(decrypted) recvPacket(" + packetString + ")");
    	} else {
    		if (DEBUG_DECRYPTED_PACKET)	System.out.println("Packet is not encrypted.");
    	}
    	
    	/** Construct the packet. */
    	pckt = new Packet(packetString);
    	
    	/** Check the integrity of the message. */
    	if (!pckt.verifyMAC(integrityProvider)) {
    		System.err.println("Packet failed MAC verification! Discarding...");
    		return null;
    	} else {
    		if (DEBUG_INTEGRITY) System.out.println("Packet passed MAC verification.");
    	}
        
    	/** Print debug information. */
        if (DEBUG_RAW_PACKET)     System.out.println("(raw)     recvPacket(" + packetString + ")");
        if (DEBUG_DECODED_PACKET) {
    		if (pckt.data.length <= 0) {
    			if (pckt.digest.length <= 0)
    				System.out.println("(decoded)   recvPacket(" + Packet.getCommandName(pckt.command) + ", null, null)");    			else
    				System.out.println("(decoded)   recvPacket(" + Packet.getCommandName(pckt.command) + ", null, " + (new String(pckt.digest)) + ")");
    		} else {
    			if (pckt.digest.length <= 0)
    				System.out.println("(decoded)   recvPacket(" + Packet.getCommandName(pckt.command) + ", " + (new String(pckt.data)).replaceAll("\n", ";") + ", null)");
    			else
    				System.out.println("(decoded)   recvPacket(" + Packet.getCommandName(pckt.command) + ", " + (new String(pckt.data)).replaceAll("\n", ";") + ", " + (new String(pckt.digest)) + ")");
    		}
    	}
        
        /** Check for special security-related packets, which we will handle here. */
        switch (pckt.command) {
	    	case Packet.CMD_PUBLICKEY:
	    		final String pubKey = new String(pckt.data);
	    		if (DEBUG_KEY_EXCHANGE) System.out.println("Received public key: " + pubKey);
	        	if (DEBUG_GENERAL) System.out.println("Performing key exchange.");
	    	    keyExchange(pubKey);
	            return null;
	        
	    	case Packet.CMD_INTEGRITYKEY:
	    		byte[] keyBytes = Base64.decodeBase64(pckt.data);
	    		final SecretKey integrityKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, HashedMessageAuthenticationCode.HMAC_ALGORITHM);
	    		if (DEBUG_INTEGRITY) System.out.println("Received HMAC key: " + getHexValue(integrityKey.getEncoded()));
	        	
	    		/** Initialise StealthNetMAC. */
	    		MessageAuthenticationCode tmp = null;
	    		if (DEBUG_GENERAL) System.out.println("Initialising HMAC.");
	        	try {
	        		tmp = new HashedMessageAuthenticationCode(integrityKey);
	        	} catch(Exception e) {
	        		System.err.println("Failed to initialise StealthNetMAC!");
	        		return null;
	        	}
	        	
	        	/** Send acknowledgement. */
	        	if (DEBUG_INTEGRITY) System.out.println("Sending acknowledgement of integrity key.");
	        	sendPacket(Packet.CMD_NULL);
	        	
	        	/** Done! */
	        	integrityProvider = tmp;
	    		return null;
    		
    		default:
    			break;
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
     * Perform a key exchange with the other party. This function is called by 
     * the peer that wishes to initiate the key exchange.
     * 
     * @see KeyExchange 
     */
    public void initKeyExchange() {
    	if (DEBUG_KEY_EXCHANGE) System.out.println("Initiating key exchange.");
    	
    	if (authenticationProvider != null) {
    		System.err.println("Key exchange has already been initialised!");
    		return;
    	}
    	
    	try {
    		if (DEBUG_KEY_EXCHANGE) System.out.println("Generating Diffie-Hellman public/private keys.");
			authenticationProvider = new DiffieHellmanKeyExchange(KEY_EXCHANGE_NUM_BITS, new SecureRandom());
			if (DEBUG_KEY_EXCHANGE) System.out.println("Generated Diffie-Hellman public/private keys.");
		} catch (Exception e) {
			System.err.println("Diffie-Hellman key exchange failed. Failed to generate public/private keys.");			
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			System.exit(1);
		}
    	
    	/** Transmit our public key. */
    	String pubKey = authenticationProvider.getPublicKey().toString();
    	if (DEBUG_KEY_EXCHANGE) System.out.println("Sending public key to peer: " + pubKey);
    	sendPacket(Packet.CMD_PUBLICKEY, pubKey);
    	if (DEBUG_KEY_EXCHANGE) System.out.println("Sent public key to peer.");
    }
    
    /**
     * Continuously receives (and discards unrelated) packets until the 
     * Diffie-Hellman key exchange has completed.
     */
    private void waitForKeyExchange() {
    	if (DEBUG_KEY_EXCHANGE) System.out.println("Waiting for successful key exchange...");
    	
    	while (sharedSecretKey == null) {
    		try {
	        	Packet pckt = recvPacket();
	            
	        	if (pckt == null)
	        		continue;
	        	
	            switch (pckt.command) {
	            	case Packet.CMD_PUBLICKEY:
	            		final String pubKey = new String(pckt.data);
	                	if (DEBUG_ENCRYPTION) System.out.println("Received a public key command. Key: \"" + pubKey + "\".");
	                	if (DEBUG_GENERAL) System.out.println("Performing key exchange.");
	            	    keyExchange(pubKey);
	                    break;
	            
	                default:
	                    System.err.println("Unexpected command received from server!");
	            }
    		} catch (IOException e) {}
        }
    }
    
    /** 
     * Perform a Diffie-Hellman key exchange with the other party. This function
     * should be called when a peer receives a public key.
     * 
     * After this function returns (unless an error occurred), the shared secret
     * key should have been established and encryption/decryption for this 
     * communication should be initialised.
     * 
     * @param publicKey The public key that was sent to us.
     * @see KeyExchange 
     */
    public void keyExchange(String publicKey) {
    	if (authenticationProvider == null) {
    		/** We haven't yet made our own private/public keys. */
    		initKeyExchange();
    	}
    	
    	/** Generate the shared key. */
		try {
			if (DEBUG_KEY_EXCHANGE) System.out.println("Generating the Diffie-Hellman shared secret key.");
			sharedSecretKey = authenticationProvider.getSharedSecret(new BigInteger(publicKey));
			if (DEBUG_KEY_EXCHANGE) {
				String sskey = new String(getHexValue(sharedSecretKey.getEncoded()));
				System.out.println("Generated Diffie-Hellman shared secret key: " + sskey);
			}
		} catch (Exception e) {
			System.err.println("Diffie-Hellman key exchange failed. Failed to generate shared secret key.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			return;
		}
		
		SecretKey cryptKey = null;
		try {
			/** Use a hash of the shared secret key for encryption and decryption. */
			if (DEBUG_ENCRYPTION) System.out.println("Generating AES encryption/decryption key.");
			MessageDigest mdb = MessageDigest.getInstance(AESEncryption.HASH_ALGORITHM);
			
			cryptKey = new SecretKeySpec(mdb.digest(sharedSecretKey.getEncoded()), AESEncryption.KEY_ALGORITHM);
			String cryptKeyString = new String(getHexValue(cryptKey.getEncoded()));
			if (DEBUG_ENCRYPTION) System.out.println("Generated AES encryption/decryption key: " + cryptKeyString);
			
			confidentialityProvider = new AESEncryption(cryptKey, cryptKey);
		} catch (Exception e) {
			System.err.println("Unable to provide encryption/decryption. Failed to generate AES encryption/decryption key or initialise ciphers.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			return;
		}
    }
    
    /** 
     * TODO 
     */
    private void doIntegrityKey() {
    	SecretKey integrityKey = null;
		try {
			if (DEBUG_INTEGRITY) System.out.println("Generating MD5 HMAC key.");
			final KeyGenerator keyGen = KeyGenerator.getInstance(HashedMessageAuthenticationCode.HMAC_ALGORITHM);
			integrityKey = keyGen.generateKey();
			final String integrityKeyString = new String(getHexValue(integrityKey.getEncoded()));
			if (DEBUG_INTEGRITY) System.out.println("Generated MD5 HMAC key: " + integrityKeyString);
			
			/** Share integrity key. */
			sendPacket(Packet.CMD_INTEGRITYKEY, Base64.encodeBase64String(integrityKey.getEncoded()));
			
			/** Wait for acknowledgement. */
			Packet pckt;
			while (true) {
				pckt = recvPacket();
				
				if (pckt == null)
					continue;
				
				if (pckt.command == Packet.CMD_NULL)
					break;
			}
			
			/** Enable HMAC. */
			integrityProvider = new HashedMessageAuthenticationCode(integrityKey);
		} catch (Exception e) {
			System.err.println("Unable to provide integrity. Failed to initialise HMAC.");
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
    private static String getHexValue(byte[] array) {
		final String hexDigitChars = "0123456789ABCDEF";
		final StringBuffer buf = new StringBuffer(array.length * 2);
		
		for (int cx = 0; cx < array.length; cx++) {
			final int hn = ((int) (array[cx]) & 0x00FF) / 16;
			final int ln = ((int) (array[cx]) & 0x000F);
			buf.append(hexDigitChars.charAt(hn));
			buf.append(hexDigitChars.charAt(ln));
		}
		return buf.toString();
	}
}

/******************************************************************************
 * END OF FILE:     Comms.java
 *****************************************************************************/