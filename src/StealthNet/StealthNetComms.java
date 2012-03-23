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
import java.security.PrivateKey;
import java.security.PublicKey;

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
	/** Set to true to output debug messages for this class. */
	private static final boolean DEBUG = (System.getProperties().getProperty("debug." + StealthNetComms.class.getName()) == "true");
	
	/** Default host for the StealthNet server. */
    public static final String DEFAULT_SERVERNAME = "localhost";
    
    /** Default port for the StealthNet server. */
    public static final int DEFAULT_SERVERPORT = 5616;
    
    /** Current host. */
    public String servername;
    
    /** Current port. */
    public int port;

    /** Opened socket through which the communication is to be made. */
    private Socket commsSocket;

    /** Output data stream for the socket. */
    private PrintWriter dataOut;            
    
    /** Input data stream for the socket. */
    private BufferedReader dataIn;    
    
    /** Constructor. */
    public StealthNetComms() {
        new StealthNetComms(DEFAULT_SERVERNAME, DEFAULT_SERVERPORT);
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
    }

    /** 
     * Cleans up before terminating the class. 
     * @throws IOException
     */
    protected void finalize() throws IOException {
        if (dataOut != null) dataOut.close();
        if (dataIn != null) dataIn.close();
        if (commsSocket != null) commsSocket.close();
    }

    /** 
     * Initiates a communications session. 
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
     * Accepts a connection on the given socket.
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
        if (DEBUG) System.out.println("String data: " + data);
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
        pckt = new StealthNetPacket(str);
        return pckt;
    }

    /**
     * Checks if the class is ready to receive more data.  
     * 
     * @return True to indicate ready-to-receive. False to indicate not-ready.
     * @throws IOException
     */
    public boolean recvReady() throws IOException {
    	if (DEBUG) {
	        System.out.println("Connected: " + commsSocket.isConnected());
	        System.out.println("Closed: " + commsSocket.isClosed());
	        System.out.println("InClosed: " + commsSocket.isInputShutdown());
	        System.out.println("OutClosed: " + commsSocket.isOutputShutdown());
    	}
        return dataIn.ready();
    }
}

/******************************************************************************
 * END OF FILE:     StealthNetComms.java
 *****************************************************************************/