/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet
 * FILENAME:        Comms.java
 * AUTHORS:         Stephen Gould, Matt Barrie, Ryan Junee and Joshua Spence
 * DESCRIPTION:     Implementation of StealthNet Communications for ELEC5616
 *                  programming assignment.
 *                  
 *                  Security protocols have been added to this class in an 
 *                  attempt to make StealthNet communications secure. In 
 *                  particular, Diffie-Hellman key exchange is performed to 
 *                  provide authentication. AES encryption is performed to 
 *                  ensure confidentiality. Hashed Message Authentication Codes
 *                  (HMACs) are used to verify message integrity. Finally, a 
 *                  PRNG is used to provide nonces in order to provide reply 
 *                  prevention.
 *                  
 *                  Debug code has also been added to this class.
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
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import StealthNet.Security.AESEncryption;
import StealthNet.Security.AsymmetricEncryption;
import StealthNet.Security.DiffieHellmanKeyExchange;
import StealthNet.Security.Encryption;
import StealthNet.Security.HashedMessageAuthenticationCode;
import StealthNet.Security.KeyExchange;
import StealthNet.Security.MessageAuthenticationCode;
import StealthNet.Security.PRNGNonceGenerator;
import StealthNet.Security.NonceGenerator;
import StealthNet.Security.RSAAsymmetricEncryption;

/* StealthNet.Comms class ****************************************************/

/**
 * A class to buffered write and buffered read to and from an opened socket. 
 * Enables bidirectional communication between two StealthNet peers. This class,
 * before allowing communications between the parties, secures the communication
 * by establishing several security protocols.
 * 
 * @author Stephen Gould
 * @author Matt Barrie
 * @author Ryan Junee
 * @author Joshua Spence
 */
public class Comms {
	/** Debug options. */
	private static final boolean DEBUG_GENERAL               = Debug.isDebug("StealthNet.Comms.General");
	private static final boolean DEBUG_ERROR_TRACE           = Debug.isDebug("StealthNet.Comms.ErrorTrace") || Debug.isDebug("ErrorTrace");
	private static final boolean DEBUG_PURE_PACKET           = Debug.isDebug("StealthNet.Comms.PureOutput");
	private static final boolean DEBUG_DECODED_PACKET        = Debug.isDebug("StealthNet.Comms.DecodedOutput");
	private static final boolean DEBUG_ENCRYPTED_PACKET      = Debug.isDebug("StealthNet.Comms.EncryptedOutput");
	private static final boolean DEBUG_DECRYPTED_PACKET      = Debug.isDebug("StealthNet.Comms.DecryptedOutput");
	private static final boolean DEBUG_RAW_PACKET            = Debug.isDebug("StealthNet.Comms.RawOutput");
	private static final boolean DEBUG_RECEIVE_READY         = Debug.isDebug("StealthNet.Comms.ReceiveReady");
	private static final boolean DEBUG_AUTHENTICATION        = Debug.isDebug("StealthNet.Comms.Authentication");
	private static final boolean DEBUG_ENCRYPTION            = Debug.isDebug("StealthNet.Comms.Encryption");
	private static final boolean DEBUG_INTEGRITY             = Debug.isDebug("StealthNet.Comms.Integrity");
	private static final boolean DEBUG_REPLAY_PREVENTION     = Debug.isDebug("StealthNet.Comms.ReplayPrevention");
	private static final boolean DEBUG_ASYMMETRIC_ENCRYPTION = Debug.isDebug("StealthNet.Comms.AsymmetricEncryption");
	
	/** Defaults. */
    public static final String DEFAULT_SERVERNAME = "localhost";	/** Default host for the StealthNet server. */
    public static final int DEFAULT_SERVERPORT = 5616;				/** Default port for the StealthNet server. */
    public static final String DEFAULT_BANKNAME = "localhost";		/** Default host for the StealthNet bank. */
    public static final int DEFAULT_BANKPORT = 5617;				/** Default port for the StealthNet bank. */
    
    /** Current values. */
    private final String serverName;	/** This host - defaults to DFEAULT_SERVERNAME */
    private final int port;				/** This port - defaults to DEFAULT_SERVERPORT. */

    /** Opened socket through which the communication is to be made. */
    private Socket commsSocket;
    
    /** 
     * Provides asymmetric encryption. Asymmetric encryption will be used until 
     * symmetric encryption can be used.
     */
    private final AsymmetricEncryption asymmetricEncryptionProvider;
    private boolean peerHasPublicKey = false;
    
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
	private NonceGenerator replayPreventionTX = null;
	private NonceGenerator replayPreventionRX = null;

    /** Output data stream for the socket. */
    private PrintWriter dataOut;            
    
    /** Input data stream for the socket. */
    private BufferedReader dataIn;
    
    /** Constructor without asymmetric encryption. */
    public Comms() {
    	this.commsSocket = null;
    	this.dataIn = null;
    	this.dataOut = null;
        
        this.serverName = DEFAULT_SERVERNAME;
        this.port = DEFAULT_SERVERPORT;
        
        this.asymmetricEncryptionProvider = null;
        
        if (DEBUG_GENERAL) System.out.println("Creating Comms to " + this.serverName + " on port " + this.port + ".");
    }
    
    /** 
     * Constructor with asymmetric encryption. 
     *
     * @param aep To provide asymmetric encryption and public-private keys.
     */
    public Comms(AsymmetricEncryption aep) {
    	this.commsSocket = null;
    	this.dataIn = null;
    	this.dataOut = null;
        
        this.serverName = DEFAULT_SERVERNAME;
        this.port = DEFAULT_SERVERPORT;
        
        this.asymmetricEncryptionProvider = aep;
        if (this.asymmetricEncryptionProvider != null && this.asymmetricEncryptionProvider.getPeerPublicKey() != null)
        	if (DEBUG_ASYMMETRIC_ENCRYPTION) System.out.println("Asymmetric encryption enabled using public key: " + new String(Utility.getHexValue(asymmetricEncryptionProvider.getPeerPublicKey().getEncoded())));
        this.confidentialityProvider = this.asymmetricEncryptionProvider;
        
        if (DEBUG_GENERAL) System.out.println("Creating Comms to " + this.serverName + " on port " + this.port + ".");
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
        
        this.serverName = s;
        this.port = p;
        
        this.asymmetricEncryptionProvider = null;
        
        if (DEBUG_GENERAL) System.out.println("Creating Comms to " + this.serverName + " on port " + this.port + ".");
    }
    
    /** 
     * Constructor. 
     * 
     * @param s The servername of the StealthNet server.
     * @param p The port number for the StealthNet server.
     * @param aep To provide asymmetric encryption and public-private keys.
     */
    public Comms(String s, int p, AsymmetricEncryption aep) {    	
    	this.commsSocket = null;
        this.dataIn = null;
        this.dataOut = null;
        
        this.serverName = s;
        this.port = p;
        
        this.asymmetricEncryptionProvider = aep;
        if (this.asymmetricEncryptionProvider != null && this.asymmetricEncryptionProvider.getPeerPublicKey() != null)
        	if (DEBUG_ASYMMETRIC_ENCRYPTION) System.out.println("Asymmetric encryption enabled using public key: " + new String(Utility.getHexValue(asymmetricEncryptionProvider.getPeerPublicKey().getEncoded())));
        this.confidentialityProvider = this.asymmetricEncryptionProvider;
        
        if (DEBUG_GENERAL) System.out.println("Creating Comms to " + this.serverName + " on port " + this.port + ".");
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
     * replay prevention nonce).
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
        
        /** 
         * NOTE: All communications from here will be encrypted with asymmetric 
         * encryption.
         */
        
        /** Send the peer our public key for asymmetric encryption. */	
        sendPublicKey();
        
        /** Perform key exchange (Diffie-Hellman key exchange). */
        initKeyExchange();
        
        /** Wait for key exchange to finish. */
        waitForKeyExchange();
        
        /** Encrypt the communications. */
        initEncryption();
        
        /** 
         * NOTE: All communications from here will be encrypted with symmetric 
         * encryption.
         */
        
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
     * server side. Once the socket has been created, the peer waits for the
     * other party to initiate all of the relevant security protocols.
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
            return false;
        }
        
        /** 
         * NOTE: All communications from here will be encrypted with asymmetric 
         * encryption.
         */
        
        /** 
         * Wait for the peer to send their public key so that we can encrypt 
         * outgoing communications.
         */
        recvPublicKey();
        
        /** 
         * Wait for key exchange (Diffie-Hellman key exchange) to occur. This 
         * should be initiated on the other end of the communications.
         */
        waitForKeyExchange();
        
        /** Encrypt the communications. */
        initEncryption();
        
        /** 
         * NOTE: All communications from here will be encrypted with symmetric 
         * encryption.
         */
        
        /** 
         * Wait for integrity key exchange to occur. This should be initiated on
         * the other end of the communications.  
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
        final DecryptedPacket pckt = new DecryptedPacket(command, data, dataSize, integrityProvider, replayPreventionTX);
        return sendPacket(pckt);
    }

    /**
     * Sends a StealthNet packet by writing it to the print writer for the 
     * socket. Before the packet is transmitted it is encrypted, if encryption
     * has been initiated. If not, then the packet will be transmitted in its
     * unencrypted form. Beware that this may not always be the desired effect.
     * 
     * If we are using asymmetric encryption, then the packet will only be 
     * encrypted if we know the peer's public key value.
     * 
     * @param decPckt The packet to be sent.
     * @return True if successful, otherwise false.
     */
    public boolean sendPacket(DecryptedPacket decPckt) {    	
    	/** Print debug information. */
    	if (DEBUG_PURE_PACKET)
			System.out.println("(pure)      sendPacket(" + decPckt.toString() + ")");
    	if (DEBUG_DECODED_PACKET)
			System.out.println("(decoded)   sendPacket(" + decPckt.getDecodedString() + ")");
    	
    	/** 
    	 * Encrypt the packet. If confidentialityProvider is null, then the 
    	 * EncryptionPacket will not actually be encrypted in any way, but 
    	 * rather will contain the unencrypted packet contents.
    	 * 
    	 * If confidentialityProvider is an AsymmetricEncryption instance, then
    	 * encryption will only be provided if the peer's public key is known.
    	 */
    	EncryptedPacket encPckt;
    	try {
    		if ((confidentialityProvider != null) && (confidentialityProvider instanceof AsymmetricEncryption) && (((AsymmetricEncryption) confidentialityProvider).getPeerPublicKey() != null))
    			encPckt = decPckt.encrypt(confidentialityProvider);
    		else
    			encPckt = decPckt.encrypt(null);
		} catch (Exception e) {
			System.err.println("Failed to encrypt packet!");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			return false;
		}
		if ((confidentialityProvider != null) && DEBUG_ENCRYPTED_PACKET)	
			System.out.println("(encrypted) sendPacket(" + encPckt.getEncryptedString() + ")");
		
		if (DEBUG_RAW_PACKET)
			System.out.println("(raw)       sendPacket(" + encPckt.toString() + ")");
    	
        if (dataOut == null) {
        	System.err.println("PrintWriter does not exist!");
            return false;
        }
        
        /** Print the packet to the output writer. */
        dataOut.println(encPckt.toString());
        return true;
    }

    /**
     * Reads a StealthNet packet from the buffered reader for the socket. Note
     * that this function should (in the normal case) not return any security
     * related packets (CMD_AUTHENTICATIONKEY, CMD_INTEGRITYKEY, CMD_NONCESEED).
     * 
     * If any step (such as decryption) of an incoming packet fails, then this
     * function will recursively call itself. The result is that the only 
     * situation in which this function returns null is when the communications
     * have in some way been closed.
     * 
     * Note that the string received by the buffered data reader represents an
     * EncryptedPacket. This function will attempt to decrypt this packet (into
     * a DecryptedPacket) before returning the packet to the user.
     * 
     * @return The packet that was received.
     */
    public DecryptedPacket recvPacket() throws IOException {
        /** Read data from the input buffer. */
        String packetString = dataIn.readLine();
        
        if (packetString == null)
        	return null;
        
        /** Debug information. */
        if (DEBUG_RAW_PACKET)
    			System.out.println("(raw)       recvPacket(" + packetString + ")");
        
        /** Construct the packet. */
        EncryptedPacket encPckt = null;
    	try {
    		encPckt = new EncryptedPacket(packetString, HashedMessageAuthenticationCode.DIGEST_BYTES);
    	} catch (Exception e) {
    		if (DEBUG_GENERAL) System.err.println("Unable to instantiate packet. Discarding...");
    		
    		/** Retrieve another packet by recursion. */
    		return recvPacket();
    	}
    	
    	/** Check the integrity of the message. */
    	if (integrityProvider != null) {
    		try {
		    	if (!encPckt.verifyMAC(integrityProvider)) {
					System.err.println("(verified)  recvPacket - Packet failed MAC verification! Discarding...");
					
					/** Retrieve another packet by recursion. */
		    		return recvPacket();
		    	} else {
		    		if (DEBUG_INTEGRITY) 
	    				System.out.println("(verified)  recvPacket - Packet passed MAC verification.");
		    	}
    		}  catch (Exception e) {
        		if (DEBUG_GENERAL) System.err.println("Unable to verify packet. Discarding...");
        		
        		/** Retrieve another packet by recursion. */
        		return recvPacket();
        	}
    	}
        
        /** 
         * Attempt to decrypt the packet. If we are using asymmetric encryption,
         * then we cannot decrypt the packet until we are sure that the peer has
         * received our public key (because otherwise the peer would not be able
         * to encrypt the message).
         */
    	DecryptedPacket decPckt = null;
		try {
			if ((confidentialityProvider != null) && (confidentialityProvider instanceof AsymmetricEncryption) && !peerHasPublicKey)
				decPckt = encPckt.decrypt(null);
			else
				decPckt = encPckt.decrypt(confidentialityProvider);
		} catch (Exception e) {
			if (DEBUG_GENERAL) System.err.println("Failed to decrypt packet! Discarding...");
			
			/** Retrieve another packet by recursion. */
    		return recvPacket();
		}
		/** Print debug information. */
		if (DEBUG_DECRYPTED_PACKET)	
			System.out.println("(decrypted) recvPacket(" + decPckt.toString() + ")");
		else if (DEBUG_RAW_PACKET)
			System.out.println("(raw)       recvPacket(" + decPckt.toString() + ")");
		if (DEBUG_DECODED_PACKET)
			System.out.println("(decoded)   recvPacket(" + decPckt.getDecodedString() + ")");
        
        if (replayPreventionRX != null) {
        	if (!replayPreventionRX.isAllowed(decPckt.nonce)) {
				if (DEBUG_GENERAL)
					System.err.println("(verified)  recvPacket - Packet failed replay prevention! Discarding...");
				
				/** Retrieve another packet by recursion. */
	    		return recvPacket();
        	} else {
        		if (DEBUG_INTEGRITY) 
    				System.out.println("(verified)  recvPacket - Packet passed replay prevention.");
        	}
        }
        
        /** Done. Return the packet. */
        return decPckt;
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
     * Send the peer our public key for asymmetric encryption. Once we have 
     * received acknowledgement that the peer has our public key value, the peer
     * will be able to encrypt messages to us.
     */
    private void sendPublicKey() {
    	if (DEBUG_ASYMMETRIC_ENCRYPTION) System.out.println("Sending the peer our public key.");
    	
    	/** Transmit our public key. */
    	final byte[] pubKeyBytes = asymmetricEncryptionProvider.getPublicKey().getEncoded();
    	final String pubKeyString = new String(Utility.getHexValue(pubKeyBytes));
    	if (DEBUG_ASYMMETRIC_ENCRYPTION) System.out.println("Sending public key to peer: " + pubKeyString);
    	sendPacket(DecryptedPacket.CMD_PUBLICKEY, Base64.encodeBase64String(pubKeyBytes));
    	if (DEBUG_ASYMMETRIC_ENCRYPTION) System.out.println("Sent public key to peer.");
    	
    	/** Wait for acknowledgement. */
    	DecryptedPacket pckt = new DecryptedPacket();
    	while (!peerHasPublicKey) {
    		try {
	        	pckt = recvPacket();
	            
	        	if (pckt == null)
	        		break;
	        	
	        	switch (pckt.command) {
	            	case DecryptedPacket.CMD_NULL:
	            		peerHasPublicKey = true;
            			break;
	            }
    		} catch (IOException e) {}
        }
    }
    
    /** 
     * Receive the peer's public key for asymmetric encryption. Send an 
     * acknowledgement to the peer and then enable asymmetric encryption.
     */
    private void recvPublicKey() {
    	if (DEBUG_ASYMMETRIC_ENCRYPTION) System.out.println("Waiting for peer public key...");
    	
    	while (asymmetricEncryptionProvider.getPeerPublicKey() == null) {
    		try {
	        	DecryptedPacket pckt = recvPacket();
	            
	        	if (pckt == null)
	        		break;
	        	
	            switch (pckt.command) {
	            	case DecryptedPacket.CMD_PUBLICKEY:
	            		/** Set the peer's public key. */
	            		final byte[] pubKeyBytes = Base64.decodeBase64(pckt.data);
	            		final String pubKeyString = new String(Utility.getHexValue(pubKeyBytes));
	            		if (DEBUG_ASYMMETRIC_ENCRYPTION) System.out.println("Received an asymmetric public key. Key: \"" + pubKeyString + "\".");
	            		
	            		final KeyFactory factory = KeyFactory.getInstance(RSAAsymmetricEncryption.ALGORITHM);
	            		final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubKeyBytes);
	            		final PublicKey pubKey = factory.generatePublic(keySpec);
	            		
	            		/** Send acknowledgement. */
	            		sendPacket(DecryptedPacket.CMD_NULL);
	            		
	            		/** Enable asymmetric encryption. */
	            		asymmetricEncryptionProvider.setPeerPublicKey(pubKey);
	                    break;
	            }
    		} catch (Exception e) {}
        }
    }
    
    /** 
     * Perform a key exchange with the other party. This function is called by 
     * the peer that wishes to initiate the key exchange (ie. the peer that 
     * initiated the session).
     */
    private void initKeyExchange() {
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
    	sendPacket(DecryptedPacket.CMD_AUTHENTICATIONKEY, pubKey);
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
	        	DecryptedPacket pckt = recvPacket();
	            
	        	if (pckt == null)
	        		break;
	        	
	            switch (pckt.command) {
	            	case DecryptedPacket.CMD_AUTHENTICATIONKEY:
	            		final String pubKey = new String(pckt.data);
	                	if (DEBUG_ENCRYPTION) System.out.println("Received a public key command. Key: \"" + pubKey + "\".");
	                	if (DEBUG_GENERAL) System.out.println("Performing key exchange.");
	            	    keyExchange(pubKey);
	                    break;
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
    private void keyExchange(String publicKey) {
    	if (authenticationProvider == null) {
    		/** We haven't yet made our own private/public keys. */
    		initKeyExchange();
    	}
    	
    	/** Generate the shared key. */
		try {
			if (DEBUG_AUTHENTICATION) System.out.println("Generating the Diffie-Hellman shared secret key.");
			authenticationKey = authenticationProvider.getSharedSecret(new BigInteger(publicKey));
			if (DEBUG_AUTHENTICATION) {
				final String sskey = new String(Utility.getHexValue(authenticationKey.getEncoded()));
				System.out.println("Generated Diffie-Hellman shared secret key: " + sskey);
			}
		} catch (Exception e) {
			System.err.println("Diffie-Hellman key exchange failed. Failed to generate shared secret key.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			return;
		}
    }
    
    /** 
     * Enable encryption on the communications, using a hash of the shared 
     * secret key as the encryption and decryption keys.
     * 
     * After this function returns (unless an error occurred), encryption and 
     * decryption for this communication should be initialised.
     */
    private void initEncryption() {
    	if (authenticationKey == null) {
    		System.err.println("Shared secret key has not yet been generated. Cannot create encryption key.");
    		System.exit(1);
    	}
		
		try {
			/** Use a hash of the shared secret key for encryption and decryption. */
			if (DEBUG_ENCRYPTION) System.out.println("Generating AES encryption/decryption key.");
			final MessageDigest mdb = MessageDigest.getInstance(AESEncryption.HASH_ALGORITHM);
			
			confidentialityKey = new SecretKeySpec(mdb.digest(authenticationKey.getEncoded()), AESEncryption.KEY_ALGORITHM);
			final String cryptKeyString = new String(Utility.getHexValue(confidentialityKey.getEncoded()));
			if (DEBUG_ENCRYPTION) System.out.println("Generated AES encryption/decryption key: " + cryptKeyString);
			
			confidentialityProvider = new AESEncryption(confidentialityKey);
		} catch (Exception e) {
			System.err.println("Unable to provide encryption/decryption. Failed to generate AES encryption/decryption key or initialise ciphers.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			return;
		}
    }
    
    /** 
     * Enable Message Authentication Codes (MACs) on the communications. 
     * Generates a key for the HMAC and transmits it to the other peer.
     */
    private void initIntegrityKey() {
    	if (DEBUG_INTEGRITY) System.out.println("Initiating integrity key.");
    	String integrityKeyString = null;
		try {
			if (DEBUG_INTEGRITY) System.out.println("Generating SHA1 HMAC key.");
			final KeyGenerator keyGen = KeyGenerator.getInstance(HashedMessageAuthenticationCode.HMAC_ALGORITHM);
			integrityKey = keyGen.generateKey();
			integrityKeyString = new String(Utility.getHexValue(integrityKey.getEncoded()));
			if (DEBUG_INTEGRITY) System.out.println("Generated SHA1 HMAC key: " + integrityKeyString);
		} catch (Exception e) {
			System.err.println("Unable to provide integrity. Failed to initialise HMAC.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			System.exit(1);
		}
		
		/** Transmit our integrity key. */
    	if (DEBUG_AUTHENTICATION) System.out.println("Sending integrity key to peer: " + integrityKeyString);
    	sendPacket(DecryptedPacket.CMD_INTEGRITYKEY, Base64.encodeBase64String(integrityKey.getEncoded()));
    	if (DEBUG_AUTHENTICATION) System.out.println("Sent integrity key to peer.");
    }
    
    /**
     * Continuously receives (and discards unrelated) packets until the 
     * integrity key exchange has completed. This is acknowledged by a NULL 
     * packet from the other peer.
     */
    private void waitForIntegrityKey() {
    	if (DEBUG_INTEGRITY) System.out.println("Waiting for successful integrity key exchange...");
    	
    	DecryptedPacket pckt = new DecryptedPacket();
    	boolean done = false;
    	while (!done) {
    		try {
	        	pckt = recvPacket();
	            
	        	if (pckt == null)
	        		break;
	        	
	        	switch (pckt.command) {
	            	case DecryptedPacket.CMD_INTEGRITYKEY:
	            	    byte[] keyBytes = Base64.decodeBase64(pckt.data);
	    	    		integrityKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, HashedMessageAuthenticationCode.HMAC_ALGORITHM);
	    	    		if (DEBUG_INTEGRITY) System.out.println("Received HMAC key: " + Utility.getHexValue(integrityKey.getEncoded()));
	    	        	
	    	        	/** Send acknowledgement. */
	    	        	if (DEBUG_INTEGRITY) System.out.println("Sending acknowledgement of integrity key.");
	    	        	sendPacket(DecryptedPacket.CMD_NULL);
	    	        	
	    	        	/** Done! */
	                    done = true;
	                    break;
	                 
	            	case DecryptedPacket.CMD_NULL:
            			if (integrityKey != null)
            				done = true;
            			break;
	            }
    		} catch (IOException e) {}
        }
    	
    	/** Done. Enable integrity provision. */
    	try {
    		if (DEBUG_INTEGRITY) System.out.println("Initiating hashed MAC provider with key: " + Utility.getHexValue(integrityKey.getEncoded()));
			integrityProvider = new HashedMessageAuthenticationCode(integrityKey);
		} catch (Exception e) {
			System.err.println("Failed to initiate integrity provider.");			
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			System.exit(1);
		}
    }
    
    /** 
     * Initiates replay prevention. Generates a seeded pseudo-random number for
     * nonce generation, and then transmits the seed to the peer.
     */
    private void initReplayPrevention() {
    	byte[] rxSeed = null;
    	
    	if (DEBUG_REPLAY_PREVENTION) System.out.println("Initiating replay prevention.");
		try {
			if (DEBUG_REPLAY_PREVENTION) System.out.println("Generating PRNG.");
			replayPreventionRX = new PRNGNonceGenerator();
			rxSeed = replayPreventionRX.getSeed();
			if (DEBUG_REPLAY_PREVENTION) System.out.println("Generated PRNG with seed: " + Utility.getHexValue(rxSeed));
		} catch (Exception e) {
			System.err.println("Unable to provide replay prevention. Failed to initialise PRNG.");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			System.exit(1);
		}
		
		/** Transmit our replay prevention seed. */
    	if (DEBUG_REPLAY_PREVENTION) System.out.println("Sending replay prevention seed to peer: " + Utility.getHexValue(rxSeed));
    	sendPacket(DecryptedPacket.CMD_NONCESEED, rxSeed);
    	if (DEBUG_REPLAY_PREVENTION) System.out.println("Sent replay prevention seed to peer.");
    }
    
    /**
     * Continuously receives (and discards unrelated) packets until the 
     * pseudo-random number generation seed exchange has completed.
     */
    private void waitForReplayPreventionSeed() {
    	if (DEBUG_REPLAY_PREVENTION) System.out.println("Waiting for successful replay prevention seed exchange...");
    	
    	DecryptedPacket pckt = new DecryptedPacket();
    	boolean done = false;
    	while (!done) {
    		try {
	        	pckt = recvPacket();
	            
	        	if (pckt == null)
	        		break;
	        	
	        	switch (pckt.command) {
	            	case DecryptedPacket.CMD_NONCESEED:
	            		byte[] txSeed = pckt.data;
	    	    		if (DEBUG_REPLAY_PREVENTION) System.out.println("Received replay prevention seed: " + Utility.getHexValue(txSeed));
	    	        	
	    	    		try {
	    	    			replayPreventionTX = new PRNGNonceGenerator(txSeed);
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
	            }
    		} catch (IOException e) {}
        }
    }
}

/******************************************************************************
 * END OF FILE:     Comms.java
 *****************************************************************************/