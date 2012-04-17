/******************************************************************************
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
 *****************************************************************************/

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
import StealthNet.Security.Encryption;
import StealthNet.Security.HashedMessageAuthenticationCode;
import StealthNet.Security.KeyExchange;
import StealthNet.Security.MessageAuthenticationCode;
import StealthNet.Security.PRNGTokenGenerator;
import StealthNet.Security.TokenGenerator;

/* StealthNet.Comms class ****************************************************/

/**
 * A class to buffered write and buffered read to and from an opened socket.
 * 
 * @author Stephen Gould
 * @author Matt Barrie
 * @author Ryan Junee
 * @author Joshua Spence
 */
public class Comms {
	/** Debug options. */
	private static final boolean DEBUG_GENERAL            = Debug.isDebug("StealthNet.Comms.General");
	private static final boolean DEBUG_ERROR_TRACE        = Debug.isDebug("StealthNet.Comms.ErrorTrace") || Debug.isDebug("ErrorTrace");
	private static final boolean DEBUG_RAW_PACKET         = Debug.isDebug("StealthNet.Comms.RawOutput");
	private static final boolean DEBUG_DECODED_PACKET     = Debug.isDebug("StealthNet.Comms.DecodedOutput");
	private static final boolean DEBUG_ENCRYPTED_PACKET   = Debug.isDebug("StealthNet.Comms.EncryptedOutput");
	private static final boolean DEBUG_DECRYPTED_PACKET   = Debug.isDebug("StealthNet.Comms.DecryptedOutput");
	private static final boolean DEBUG_RECEIVE_READY      = Debug.isDebug("StealthNet.Comms.ReceiveReady");
	private static final boolean DEBUG_AUTHENTICATION     = Debug.isDebug("StealthNet.Comms.Authentication");
	private static final boolean DEBUG_ENCRYPTION         = Debug.isDebug("StealthNet.Comms.Encryption");
	private static final boolean DEBUG_INTEGRITY          = Debug.isDebug("StealthNet.Comms.Integrity");
	private static final boolean DEBUG_REPLAY_PREVENTION  = Debug.isDebug("StealthNet.Comms.ReplayPrevention");
	
	/** Defaults. */
    public static final String DEFAULT_SERVERNAME = "localhost";	/** Default host for the StealthNet server. */
    public static final int DEFAULT_SERVERPORT = 5616;				/** Default port for the StealthNet server. */
    
    /** Current values. */
    private final String servername;	/** This host - defaults to DFEAULT_SERVERNAME */
    private final int port;				/** This port - defaults to DEFAULT_SERVERPORT. */

    /** Opened socket through which the communication is to be made. */
    private Socket commsSocket;
    
    /** Provides authentication for the communication. */
	private final static int KEY_EXCHANGE_NUM_BITS = 1024;
    private KeyExchange authenticationProvider = null;
    private SecretKey authenticationKey = null;
    
    /** Provides encryption and decryption for the communications. */
	private Encryption confidentialityProvider = null;
	private SecretKey confidentialityKey = null;
    
    /** Provides integrity through creating checksums for messages. */
	private MessageAuthenticationCode integrityProvider = null;
	private SecretKey integrityKey = null;
    
    /** Prevents replay attacks using a PRNG. */
	private TokenGenerator replayPreventionTX = null;
	private TokenGenerator replayPreventionRX = null;

    /** Output data stream for the socket. */
    private PrintWriter dataOut;            
    
    /** Input data stream for the socket. */
    private BufferedReader dataIn;
    
    /** Constructor. */
    public Comms() {
    	this.commsSocket = null;
    	this.dataIn = null;
    	this.dataOut = null;
        
        this.servername = DEFAULT_SERVERNAME;
        this.port = DEFAULT_SERVERPORT;
        
        if (DEBUG_GENERAL) System.out.println("Creating Comms to " + this.servername + " on port " + this.port + ".");
    }
    
    /** 
     * Constructor. 
     * 
     * @param s The servername of the StealthNet server.
     * @param p The port number for the StealthNet server.
     */
    public Comms(String s, int p) {    	
    	this.commsSocket = null;
        this.dataIn = null;
        this.dataOut = null;
        
        this.servername = s;
        this.port = p;
        
        if (DEBUG_GENERAL) System.out.println("Creating Comms to " + this.servername + " on port " + this.port + ".");
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
     * Initiates a communications session. This usually occurs on the client 
     * side. The peer that initiates the session is also responsible for 
     * initiating the security features (key exchange, encryption, MAC and 
     * replay prevention token).
     * 
     * @param socket The socket through which the connection is made. 
     * @return True if the initialisation succeeds. False if the initialisation 
     * fails. 
     */
    public boolean initiateSession(Socket socket) {
    	if (DEBUG_GENERAL) System.out.println("Initiating Comms session.");
        try {
            commsSocket = socket;
            dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
            dataIn = new BufferedReader(new InputStreamReader(commsSocket.getInputStream()));
        } catch (Exception e) {
            System.err.println("Connection terminated!");
            if (DEBUG_ERROR_TRACE) e.printStackTrace();
            return false;
        }
        
        /** Perform key exchange (Diffie-Hellman key exchange). */
        initKeyExchange();
        
        /** Wait for key exchange to finish. */
        waitForKeyExchange();
        
        /** Encrypt the communications. */
        initEncryption();
        
        /** Generate and transmit integrity (HMAC) key. */
        initIntegrityKey();
        
        /** Wait for the peer to send acknowledgement of integrity key. */
        waitForIntegrityKey();
        
        /** Generate and transmit replay prevention RX seed (PRNG seed). */ 
        initReplayPrevention();
        
        /** Wait for the peer to send replay prevention TX seed (PRNG seed). */
        waitForReplayPreventionSeed();
        
        return true;
    }

    /** 
     * Accepts a connection on the given socket. This usually occurs on the 
     * server side.
     * 
     * @param socket The socket through which the connection is made. 
     * @return True if the initialisation succeeds. False if the initialisation 
     * fails. 
     */
    public boolean acceptSession(Socket socket) {
    	if (DEBUG_GENERAL) System.out.println("Accepting Comms session on port " + socket.getPort() + ".");
        try {
            commsSocket = socket;
            dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
            dataIn = new BufferedReader(new InputStreamReader(commsSocket.getInputStream()));
        } catch (Exception e) {
            System.err.println("Connection terminated!");
            if (DEBUG_ERROR_TRACE) e.printStackTrace();
            System.exit(1);
        }
        
        /** 
         * Wait for key exchange (Diffie-Hellman key exchange) to occur. This 
         * should be initiated on the other end of the communications.
         */
        waitForKeyExchange();
        
        /** Encrypt the communications. */
        initEncryption();
        
        /** 
         * Wait for integrity key (AES key) exchange to occur. This should be 
         * initiated on the other end of the communications.  
         */
        waitForIntegrityKey();
        
        /**
         * Wait for replay prevent seed (PRNG seed) exchange to occur. This 
         * should be initiated on the other end of the communications.
         */
        waitForReplayPreventionSeed();

        return true;
    }

    /**
     * Terminates the communication session and closes the socket, print writer 
     * and buffered reader associated with the communications.
     * 
     * @return True if the termination succeeds, otherwise false.
     */
    public boolean terminateSession() {
    	if (DEBUG_GENERAL) System.out.println("Terminating Comms session.");
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
        final Packet pckt = new Packet(command, data, dataSize, integrityProvider, replayPreventionTX);
        return sendPacket(pckt);
    }

    /**
     * Sends a StealthNet packet by writing it to the print writer for the 
     * socket. Before transmitting the packet, any established security 
     * protocols are applied to the message. If any single security protocol
     * can be applied (because it hasn't yet been initialised), then the
     * application of that security protocol will be skipped. Beware that this 
     * may not always be what is wanted. This should be checked at a higher 
     * layer.
     * 
     * @param pckt The packet to be sent.
     * @return True if successful, otherwise false.
     */
    public boolean sendPacket(Packet pckt) {    	
    	/** Print debug information. */
    	if (DEBUG_RAW_PACKET)
    				System.out.println("(raw)       sendPacket(" + pckt.toString() + ")");
    	if (DEBUG_DECODED_PACKET)
    				System.out.println("(decoded)   sendPacket(" + pckt.getDecodedString() + ")");
    	
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
    		if (DEBUG_ENCRYPTED_PACKET)	
    				System.out.println("(encrypted) sendPacket(" + packetString + ")");
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
     * Reads a StealthNet packet from the buffered reader for the socket. Note
     * that this function should (in the normal case) not return any security
     * related packets (CMD_AUTHENTICATIONKEY, CMD_INTEGRITYKEY, CMD_TOKENSEED).
     * 
     * @return The packet that was received.
     */
    public Packet recvPacket() throws IOException {
        Packet pckt = null;
        
        /** Read data from the input buffer. */
        String packetString = dataIn.readLine();
        
        if (packetString == null)
        	return null;
        
        /** Debug information. */
        if (DEBUG_RAW_PACKET)
        			System.out.println("(raw)       recvPacket(" + packetString + ")");
        
        /** Attempt to decrypt the packet. */
    	if (confidentialityProvider != null) {
    		try {
				packetString = confidentialityProvider.decrypt(packetString);
			} catch (Exception e) {
				System.err.println("Failed to decrypt packet! Discarding...");
				if (DEBUG_ERROR_TRACE) e.printStackTrace();
				return null;
			}
    		if (DEBUG_DECRYPTED_PACKET)	
    				System.out.println("(decrypted) recvPacket(" + packetString + ")");
    	}
    	
    	/** Construct the packet. */
    	pckt = new Packet(packetString);
    	
    	/** Print debug information. */
        if (DEBUG_DECODED_PACKET)
        			System.out.println("(decoded)   recvPacket(" + pckt.getDecodedString() + ")");
    	
    	/** Check the integrity of the message. */
    	if (integrityProvider != null) {
	    	if (!pckt.verifyMAC(integrityProvider)) {
					System.err.println("(verified)  recvPacket - Packet failed MAC verification! Discarding...");
				
				/** Retrieve another packet by recursion. */
	    		return recvPacket();
	    	} else {
	    		if (DEBUG_INTEGRITY) 
    				System.out.println("(verified)  recvPacket - Packet passed MAC verification.");
	    	}
    	}
        
        if (replayPreventionRX != null) {
        	if (!replayPreventionRX.isAllowed(pckt.token)) {
    				System.err.println("(verified)  recvPacket - Packet failed replay prevention! Discarding...");
				
				/** Retrieve another packet by recursion. */
	    		return recvPacket();
        	} else {
        		if (DEBUG_INTEGRITY) 
    				System.out.println("(verified)  recvPacket - Packet passed replay prevention.");
        	}
        }
        
        /** Done. Return the packet. */
        return pckt;
    }

    /**
     * To limit the verbosity of output in recvReady, we will only print these 
     * values if they change.
     */
    private boolean prev_isconnected = false;
    private boolean prev_isclosed = false;
    private boolean prev_isinputshutdown = false;
    private boolean prev_isoutputshutdown = false;
    private boolean is_first_time = true;
    
    /**
     * Checks if the class is ready to receive more data.  
     * 
     * @return True to indicate ready-to-receive. False to indicate not-ready.
     * @throws IOException
     */
    public boolean recvReady() throws IOException {
    	/**
         * To limit the verbosity of output in recvReady, we will only print 
         * these values if they change.
         */
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
    	
    	/** Return the result - the only real useful code in this function. */
        return dataIn.ready();
    }
    
    /** 
     * Perform a key exchange with the other party. This function is called by 
     * the peer that wishes to initiate the key exchange (ie. the peer that 
     * initiated the session).
     */
    public void initKeyExchange() {
    	if (DEBUG_AUTHENTICATION) System.out.println("Initiating key exchange.");
    	
    	if (authenticationProvider != null) {
    		System.err.println("Key exchange has already been initialised!");
    		return;
    	}
    	
    	try {
    		if (DEBUG_AUTHENTICATION) System.out.println("Generating Diffie-Hellman public/private keys.");
			authenticationProvider = new DiffieHellmanKeyExchange(KEY_EXCHANGE_NUM_BITS, new SecureRandom());
			if (DEBUG_AUTHENTICATION) System.out.println("Generated Diffie-Hellman public/private keys.");
		} catch (Exception e) {
			System.err.println("Diffie-Hellman key exchange failed. Failed to generate public/private keys.");			
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			System.exit(1);
		}
    	
    	/** Transmit our public key. */
    	String pubKey = authenticationProvider.getPublicKey().toString();
    	if (DEBUG_AUTHENTICATION) System.out.println("Sending public key to peer: " + pubKey);
    	sendPacket(Packet.CMD_AUTHENTICATIONKEY, pubKey);
    	if (DEBUG_AUTHENTICATION) System.out.println("Sent public key to peer.");
    }
    
    /**
     * Continuously receives (and discards unrelated) packets until the 
     * Diffie-Hellman key exchange has completed.
     */
    private void waitForKeyExchange() {
    	if (DEBUG_AUTHENTICATION) System.out.println("Waiting for successful authentication key exchange...");
    	
    	while (authenticationKey == null) {
    		try {
	        	Packet pckt = recvPacket();
	            
	        	if (pckt == null)
	        		continue;
	        	
	            switch (pckt.command) {
	            	case Packet.CMD_AUTHENTICATIONKEY:
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
     * should be called when a peer receives a public key (ie. by the peer that
     * accepts the communications session).
     * 
     * After this function returns (unless an error occurred), the shared secret
     * key should have been established.
     * 
     * @param publicKey The public key that was sent to us.
     */
    public void keyExchange(String publicKey) {
    	if (authenticationProvider == null) {
    		/** We haven't yet made our own private/public keys. */
    		initKeyExchange();
    	}
    	
    	/** Generate the shared key. */
		try {
			if (DEBUG_AUTHENTICATION) System.out.println("Generating the Diffie-Hellman shared secret key.");
			authenticationKey = authenticationProvider.getSharedSecret(new BigInteger(publicKey));
			if (DEBUG_AUTHENTICATION) {
				final String sskey = new String(getHexValue(authenticationKey.getEncoded()));
				System.out.println("Generated Diffie-Hellman shared secret key: " + sskey);
			}
		} catch (Exception e) {
			System.err.println("Diffie-Hellman key exchange failed. Failed to generate shared secret key.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			return;
		}
    }
    
    /** 
     * Enable encryption on the communications, using a hash of the shared secret
     * key as the encryption key.
     * 
     * After this function returns (unless an error occurred), encryption and 
     * decryption for this communication should be initialised.
     */
    public void initEncryption() {
    	if (authenticationKey == null) {
    		System.err.println("Shared secret key has not yet been generated. Cannot create encryption key.");
    		System.exit(1);
    	}
		
		try {
			/** Use a hash of the shared secret key for encryption and decryption. */
			if (DEBUG_ENCRYPTION) System.out.println("Generating AES encryption/decryption key.");
			final MessageDigest mdb = MessageDigest.getInstance(AESEncryption.HASH_ALGORITHM);
			
			confidentialityKey = new SecretKeySpec(mdb.digest(authenticationKey.getEncoded()), AESEncryption.KEY_ALGORITHM);
			final String cryptKeyString = new String(getHexValue(confidentialityKey.getEncoded()));
			if (DEBUG_ENCRYPTION) System.out.println("Generated AES encryption/decryption key: " + cryptKeyString);
			
			confidentialityProvider = new AESEncryption(confidentialityKey, confidentialityKey);
		} catch (Exception e) {
			System.err.println("Unable to provide encryption/decryption. Failed to generate AES encryption/decryption key or initialise ciphers.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			return;
		}
    }
    
    /** 
     * Enable Message Authentication Codes (MACs) on the communications. 
     * Generate a key for the HMAC and transmit it to the other peer.
     */
    private void initIntegrityKey() {
    	if (DEBUG_INTEGRITY) System.out.println("Initiating integrity key.");
    	String integrityKeyString = null;
		try {
			if (DEBUG_INTEGRITY) System.out.println("Generating MD5 HMAC key.");
			final KeyGenerator keyGen = KeyGenerator.getInstance(HashedMessageAuthenticationCode.HMAC_ALGORITHM);
			integrityKey = keyGen.generateKey();
			integrityKeyString = new String(getHexValue(integrityKey.getEncoded()));
			if (DEBUG_INTEGRITY) System.out.println("Generated MD5 HMAC key: " + integrityKeyString);
		} catch (Exception e) {
			System.err.println("Unable to provide integrity. Failed to initialise HMAC.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			System.exit(1);
		}
		
		/** Transmit our integrity key. */
    	if (DEBUG_AUTHENTICATION) System.out.println("Sending integrity key to peer with base 64 encoding: " + integrityKeyString);
    	sendPacket(Packet.CMD_INTEGRITYKEY, Base64.encodeBase64String(integrityKey.getEncoded()));
    	if (DEBUG_AUTHENTICATION) System.out.println("Sent integrity key to peer.");
    }
    
    /**
     * Continuously receives (and discards unrelated) packets until the 
     * integrity key exchange has completed. This is acknowledged by a NULL 
     * packet from the other peer.
     */
    private void waitForIntegrityKey() {
    	if (DEBUG_INTEGRITY) System.out.println("Waiting for successful integrity key exchange...");
    	
    	Packet pckt = new Packet();
    	boolean done = false;
    	while (!done) {
    		try {
	        	pckt = recvPacket();
	            
	        	if (pckt == null) {
	        		pckt = new Packet();
	        		continue;
	        	}
	        	
	        	switch (pckt.command) {
	            	case Packet.CMD_INTEGRITYKEY:
	            	    byte[] keyBytes = Base64.decodeBase64(pckt.data);
	    	    		integrityKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, HashedMessageAuthenticationCode.HMAC_ALGORITHM);
	    	    		if (DEBUG_INTEGRITY) System.out.println("Received HMAC key in base 64 encoding: " + getHexValue(integrityKey.getEncoded()));
	    	        	
	    	        	/** Send acknowledgement. */
	    	        	if (DEBUG_INTEGRITY) System.out.println("Sending acknowledgement of integrity key.");
	    	        	sendPacket(Packet.CMD_NULL);
	    	        	
	    	        	/** Done! */
	                    done = true;
	                    break;
	                 
	            	case Packet.CMD_NULL:
            			if (integrityKey != null)
            				done = true;
            			break;
	            
	                default:
	                    break;
	            }
    		} catch (IOException e) {}
        }
    	
    	/** Done. Enable integrity provision. */
    	try {
    		if (DEBUG_INTEGRITY) System.out.println("Initiating hashed MAC provider with key: " + getHexValue(integrityKey.getEncoded()));
			integrityProvider = new HashedMessageAuthenticationCode(integrityKey);
		} catch (Exception e) {
			System.err.println("Failed to initiate integrity provider.");			
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			System.exit(1);
		}
    }
    
    /** 
     * TODO
     */
    private void initReplayPrevention() {
    	Long rxSeed = null;
    	
    	if (DEBUG_REPLAY_PREVENTION) System.out.println("Initiating replay prevention.");
		try {
			if (DEBUG_REPLAY_PREVENTION) System.out.println("Generating PRNG.");
			replayPreventionRX = new PRNGTokenGenerator();
			rxSeed = new Long(replayPreventionRX.getSeed());
			if (DEBUG_REPLAY_PREVENTION) System.out.println("Generated PRNG with seed: " + rxSeed);
		} catch (Exception e) {
			System.err.println("Unable to provide replay prevention. Failed to initialise PRNG.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			System.exit(1);
		}
		
		/** Transmit our replay prevention seed. */
    	if (DEBUG_REPLAY_PREVENTION) System.out.println("Sending replay prevention seed to peer: " + rxSeed);
    	sendPacket(Packet.CMD_TOKENSEED, rxSeed.toString());
    	if (DEBUG_REPLAY_PREVENTION) System.out.println("Sent replay prevention seed to peer.");
    }
    
    /**
     * TODO
     */
    private void waitForReplayPreventionSeed() {
    	if (DEBUG_REPLAY_PREVENTION) System.out.println("Waiting for successful replay prevention seed exchange...");
    	
    	Packet pckt = new Packet();
    	boolean done = false;
    	while (!done) {
    		try {
	        	pckt = recvPacket();
	            
	        	if (pckt == null) {
	        		pckt = new Packet();
	        		continue;
	        	}
	        	
	        	switch (pckt.command) {
	            	case Packet.CMD_TOKENSEED:
	            		long txSeed = Long.parseLong(new String(pckt.data));
	    	    		if (DEBUG_REPLAY_PREVENTION) System.out.println("Received replay prevention seed: " + txSeed);
	    	        	
	    	    		try {
	    	    			replayPreventionTX = new PRNGTokenGenerator(txSeed);
	    	    		} catch (Exception e) {
	    	    			System.err.println("Unable to provide replay prevention. Failed to initialise PRNG.");
	    	    			if (DEBUG_ERROR_TRACE) e.printStackTrace();
	    	    			System.exit(1);
	    	    		}
	    	    		
	    	    		if (replayPreventionRX == null)
	    	    			initReplayPrevention();
	    	    		
	    	        	/** Done! */
	                    done = true;
	                    break;
	            
	                default:
	                    break;
	            }
    		} catch (IOException e) {}
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