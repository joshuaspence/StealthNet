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
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.NoSuchPaddingException;

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
	 * Set to true in build.xml to output debug messages for this class. 
	 * Alternatively, use the argument `-Ddebug.StealthNetComms=true' at the 
	 * command line. 
	 */
	private static final boolean DEBUG = (System.getProperty("debug.StealthNetComms", "false").equals("true"));
	
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
    
    /** Provides encryption and decryption for the communications. */
    private StealthNetEncryption confidentialityProvider;
    
    /** Provides integrity through creating checksums for messages. */
    private static final StealthNetChecksum integrityProvider = new StealthNetChecksum();
    
    /** Prevents replay attacks using a PRNG. */
    private StealthNetPRNG replayPrevention;

    /** Output data stream for the socket. */
    private PrintWriter dataOut;            
    
    /** Input data stream for the socket. */
    private BufferedReader dataIn;    
    
    /** Constructor. */
    public StealthNetComms() {
    	commsSocket = null;
        dataIn = null;
        dataOut = null;
        
        servername = DEFAULT_SERVERNAME;
        port = DEFAULT_SERVERPORT;
        
        try {
        	confidentialityProvider = new StealthNetEncryption();
        } catch (Exception e) {
        	confidentialityProvider = null;
        	System.err.println("Unable to provide confidentiality!");
        }
        replayPrevention = new StealthNetPRNG(Math.round(Math.random()));
    }
    
    /** 
     * Constructor. 
     * 
     * @param s The servername of the StealthNet server.
     * @param p The port number for the StealthNet server.
     */
    public StealthNetComms(String s, int p) {
        commsSocket = null;
        dataIn = null;
        dataOut = null;
        
        servername = s;
        port = p;
        
        try {
        	confidentialityProvider = new StealthNetEncryption();
        } catch (Exception e) {
        	confidentialityProvider = null;
        	System.err.println("Unable to provide confidentiality!");
        }
        replayPrevention = new StealthNetPRNG(Math.round(Math.random()));
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
        try {
            commsSocket = socket;
            dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
            dataIn = new BufferedReader(new InputStreamReader(commsSocket.getInputStream()));
        } catch (Exception e) {
            System.err.println("Connection terminated.");
            if (DEBUG) e.printStackTrace();
            System.exit(1);
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
        try {
            commsSocket = socket;
            dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
            dataIn = new BufferedReader(new InputStreamReader(commsSocket.getInputStream()));
        } catch (Exception e) {
            System.err.println("Connection terminated.");
            if (DEBUG) e.printStackTrace();
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
        try {
            if (commsSocket == null)
                return false;
            dataIn.close();
            dataOut.close();
            commsSocket.close();
            commsSocket = null;
        } catch (Exception e) {
        	if (DEBUG) e.printStackTrace();
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
        if (dataOut == null)
            return false;
        
        /** Print the packet to the output writer. */
        dataOut.println(pckt.toString());
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
        
        pckt = new StealthNetPacket(str);
        // Decrypt the packet
        // Check the integrity of the message.
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
    	
    	if (DEBUG && (is_first_time || (prev_isconnected != isconnected || prev_isclosed != isclosed || prev_isinputshutdown != isinputshutdown || prev_isoutputshutdown != isoutputshutdown))) {
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
}

/******************************************************************************
 * END OF FILE:     StealthNetComms.java
 *****************************************************************************/