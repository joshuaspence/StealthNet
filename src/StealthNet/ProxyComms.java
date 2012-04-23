/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet
 * FILENAME:        ProxyComms.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     Implementation of StealthNet Communications for a StealthNet
 * 					proxy.
 * IMPLEMENTS:      initiateSession();
 *                  acceptSession();
 *                  terminateSession();
 *                  sendString();
 *                  recvString();
 *                  recvReady();
 *
 *****************************************************************************/

package StealthNet;

/* Import Libraries **********************************************************/

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.SocketException;

/* StealthNet.ProxyComms class ***********************************************/

/**
 * A class to buffered write and buffered read to and from an opened socket.
 * This class is almost identical to the `Comms' class, but is stripped down to
 * provide only a basic forwarding functionality. It does not interpret packets,
 * but rather sends undecoded strings around.
 * 
 * @author Joshua Spence
 *
 */
public class ProxyComms {
	/** Debug options. */
	private static final boolean DEBUG_GENERAL       = Debug.isDebug("StealthNet.ProxyComms.General");
	private static final boolean DEBUG_ERROR_TRACE   = Debug.isDebug("StealthNet.ProxyComms.ErrorTrace") || Debug.isDebug("ErrorTrace");
	private static final boolean DEBUG_RAW_PACKET    = Debug.isDebug("StealthNet.ProxyComms.RawOutput");
	private static final boolean DEBUG_RECEIVE_READY = Debug.isDebug("StealthNet.ProxyComms.ReceiveReady");
	
	/** Defaults. */
	public static final String DEFAULT_PROXYNAME = "localhost";		/** Default host for the StealthNet proxy. */
    public static final int DEFAULT_PROXYPORT = 5618;				/** Default port for the StealthNet proxy. */
    
    /** Current values. */
    private final String servername;	/** This host - defaults to DFEAULT_SERVERNAME */
    private final int port;				/** This port - defaults to DEFAULT_SERVERPORT. */

    /** Opened socket through which the communication is to be made. */
    private Socket commsSocket;

    /** Output data stream for the socket. */
    private PrintWriter dataOut;            
    
    /** Input data stream for the socket. */
    private BufferedReader dataIn;
    
    /** Constructor. */
    public ProxyComms() {
    	this.commsSocket = null;
    	this.dataIn = null;
    	this.dataOut = null;
        
        this.servername = Comms.DEFAULT_SERVERNAME;
        this.port = Comms.DEFAULT_SERVERPORT;
        
        if (DEBUG_GENERAL) System.out.println("Creating ProxyComms to " + this.servername + " on port " + this.port + ".");
    }
    
    /** 
     * Constructor. 
     * 
     * @param s The servername of the StealthNet server.
     * @param p The port number for the StealthNet server.
     */
    public ProxyComms(String s, int p) {    	
    	this.commsSocket = null;
        this.dataIn = null;
        this.dataOut = null;
        
        this.servername = s;
        this.port = p;
        
        if (DEBUG_GENERAL) System.out.println("Creating ProxyComms to " + this.servername + " on port " + this.port + ".");
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
     * Initiates a communications session on the given socket. Note that, unlike
     * the Comms class, no security protocols are implemented here.
     * 
     * @param socket The socket through which the connection is made. 
     * @return True if the initialisation succeeds. False if the initialisation 
     * fails. 
     */
    public boolean initiateSession(Socket socket) {
    	if (DEBUG_GENERAL) System.out.println("Initiating ProxyComms session.");
        try {
            commsSocket = socket;
            dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
            dataIn = new BufferedReader(new InputStreamReader(commsSocket.getInputStream()));
        } catch (Exception e) {
            System.err.println("Connection terminated!");
            if (DEBUG_ERROR_TRACE) e.printStackTrace();
            return false;
        }
        
        return true;
    }
    
    /** 
     * Accepts a connection on the given socket. Note that, unlike the Comms 
     * class, no security protocols are implemented here.
     * 
     * @param socket The socket through which the connection is made. 
     * @return True if the initialisation succeeds. False if the initialisation 
     * fails. 
     */
    public boolean acceptSession(Socket socket) {
    	if (DEBUG_GENERAL) System.out.println("Accepting ProxyComms session on port " + socket.getPort() + ".");
        try {
            commsSocket = socket;
            dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
            dataIn = new BufferedReader(new InputStreamReader(commsSocket.getInputStream()));
        } catch (Exception e) {
            System.err.println("Connection terminated!");
            if (DEBUG_ERROR_TRACE) e.printStackTrace();
            return false;
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
    	if (DEBUG_GENERAL) System.out.println("Terminating ProxyComms session.");
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
     * Sends a string by writing it to the print writer for the socket.
     * 
     * @param str The string to be sent.
     * @return True if successful, otherwise false.
     */
    public boolean sendString(String str) throws SocketException {    	
    	/** Print debug information. */
    	if (DEBUG_RAW_PACKET) System.out.println("(raw)       sendString(" + str + ")");
    	
        if (dataOut == null) {
        	System.err.println("PrintWriter does not exist!");
            return false;
        }
        
        /** Print the packet to the output writer. */
        dataOut.println(str);
        return true;
    }

    /**
     * Reads a string from the buffered reader for the socket.
     * 
     * @return A string representing the packet that was received.
     */
    public String recvString() throws IOException, SocketException {        
        /** Read data from the input buffer. */
        final String packetString = dataIn.readLine();
        
        /** Print debug information. */
    	if (DEBUG_RAW_PACKET) System.out.println("(raw)       recvString(" + packetString + ")");
    	
    	return packetString;
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
}

/******************************************************************************
 * END OF FILE:     ProxyComms.java
 *****************************************************************************/