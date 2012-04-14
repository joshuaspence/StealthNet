/***********************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie, Stephen Gould and Ryan Junee
 *
 * PROJECT:         StealthNet
 * FILENAME:        StealthNetPacket.java
 * AUTHORS:         Matt Barrie, Stephen Gould and Ryan Junee
 * DESCRIPTION:     Implementation of StealthNet Communications for ELEC5616
 *                  programming assignment.
 *                  This code has been written for the purposes of teaching
 *                  cryptography and computer security. It is to be used as
 *                  a demonstration only. No attempt has been made to optimise
 *                  the source code.
 * VERSION:         1.0-ICE
 *
 * REVISION HISTORY:
 *
 **********************************************************************************/

package StealthNet;

/**
 * A class to store the data passed between StealthNet clients. A StealthNet
 * "packet" consists of three parts:
 *     - command
 *     - data
 *     - digest
 *  
 *  A message digest is produced by passing a StealthNetMAC instance to the 
 *  relevant function. The StealthNetPacket class will allow packets to be
 *  created without a digest (if a null StealthNetMAC instance is passed to the
 *  function). A higher layer should check whether or not this should be 
 *  allowed.
 * 
 * @author Matt Barrie
 * @author Stephen Gould
 * @author Ryan Junee
 * @author Joshua Spence (Added security-related commands. Also added 
 * getCommandName function for debug purposes.)
 */
public class StealthNetPacket {
	/** Commands. */
    public static final byte CMD_NULL = 0x00;
    public static final byte CMD_LOGIN = 0x01;
    public static final byte CMD_LOGOUT = 0x02;
    public static final byte CMD_MSG = 0x03;
    public static final byte CMD_CHAT = 0x04;
    public static final byte CMD_FTP = 0x05;
    public static final byte CMD_LIST = 0x06;
    public static final byte CMD_CREATESECRET = 0x07;
    public static final byte CMD_SECRETLIST = 0x08;
    public static final byte CMD_GETSECRET = 0x09;
    
    /** Security-specific commands. */
    public static final byte CMD_PUBLICKEY = 0x0A;
    public static final byte CMD_INTEGRITYKEY = 0x0B;
    
    /** Hexadecimal characters. */
    private static final char[] HEXTABLE = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    /** Packet contents. */
    byte command;			/** The command being sent in the packet. */      
    final byte data[];		/** The data being sent in the packet. */
    final byte[] digest;	/** The MAC digest of the packet data (in base64 encoding). */

    /** Null constructor with no digest. */
    public StealthNetPacket() {
        this.command = CMD_NULL;
        this.data = new byte[0];
        
        /** No digest is available. */
        this.digest = new byte[0];
    }

    /** 
     * Constructor with no digest. Explicitly copies the data array contents.
     *
     * @param cmd The command to be sent in the packet.
     * @param d The data to be sent in the packet.
     */
    public StealthNetPacket(byte cmd, byte[] d) {
        this.command = cmd;
        
        if (d == null)
        	this.data = new byte[0];
        else {
        	this.data = new byte[d.length];
        	System.arraycopy(d, 0, this.data, 0, d.length);
        }
        
        /** No digest is available. */
        this.digest = new byte[0];
    }
    
    /** 
     * Constructor with digest. Explicitly copies the data array contents.
     *
     * @param cmd The command to be sent in the packet.
     * @param dLen The length of the data array.
     * @param d The data to be sent in the packet.
     * @param mac The StealthNetMAC instance to provide a MAC digest.
     */
    public StealthNetPacket(byte cmd, byte[] d, int dLen, StealthNetMAC mac) {
        this.command = cmd;
        
        /** Copy the data. */
        if (d == null)
        	this.data = new byte[0];
        else  {
        	this.data = new byte[dLen];
        	System.arraycopy(d, 0, this.data, 0, dLen);
        }
        
        /** Create the MAC digest (if possible). */
        if (mac == null)
        	this.digest = new byte[0];
        else
        	this.digest = mac.createMAC(getContents()).getBytes();
    }

    /** 
     * Constructor. This function must "undo" the effects of the toString() 
     * function, because this function converts the received data into a packet.
     * 
     * @param str A string consisting of the packet contents.
     */
    public StealthNetPacket(String str) {
    	/** Add padding if necessary. */
    	if (str.length() % 2 == 1)
            str = "0" + str;
    	
        if (str.length() == 0) {
        	/** NULL packet. */
            this.command = CMD_NULL;
            this.data = new byte[0];
            this.digest = new byte[0];
        } else {
        	/** Current index of the string. */
        	int current = 0;
        	
        	/** Command (1 byte). */
            this.command = (byte) (16 * hexToInt(str.charAt(current++)) + hexToInt(str.charAt(current++)));
            
            /** Data length (2 bytes). */
            int dataLen = 4096 * hexToInt(str.charAt(current++)) + 256 * hexToInt(str.charAt(current++)) + 16 * hexToInt(str.charAt(current++)) + hexToInt(str.charAt(current++));
            
            /** Data (dataLen bytes). */
            data = new byte[dataLen];
            for (int i = 0; i < data.length; i++)
                data[i] = (byte) (16 * hexToInt(str.charAt(current++)) + hexToInt(str.charAt(current++)));
            
            /** Digest length (2 bytes). */
            int digestLen = 4096 * hexToInt(str.charAt(current++)) + 256 * hexToInt(str.charAt(current++)) + 16 * hexToInt(str.charAt(current++)) + hexToInt(str.charAt(current++));
            
            /** Digest (digestLen bytes). */
            digest = new byte[digestLen];
            for (int i = 0; i < digest.length; i++)
            	digest[i] = (byte) (16 * hexToInt(str.charAt(current++)) + hexToInt(str.charAt(current++)));
        }
    }
    
    /** 
     * Gets a string containing everything except for the MAC digest. Used to
     * compute the MAC digest.
     * 
     * @return A string representing the contents of the packet.
     */
    private String getContents() {
        String str = "";
        int lowHalfByte, highHalfByte;

        /** Command (1 byte).  */
        highHalfByte = (command >= 0) ? command : (256 + command);
        lowHalfByte = highHalfByte & 0xF;
        highHalfByte /= 16;
        str += HEXTABLE[highHalfByte];
        str += HEXTABLE[lowHalfByte];
        
        /** Data length (2 bytes). */
        final int dataLenHi = (data.length / 256);
        final int dataLenLo = (data.length % 256);
        
        /* First byte */
        highHalfByte = (dataLenHi >= 0) ? dataLenHi : (256 + dataLenHi);
        lowHalfByte = highHalfByte & 0xF;
        highHalfByte /= 16;
        str += HEXTABLE[highHalfByte];
        str += HEXTABLE[lowHalfByte];
        
        /* Second byte */
        highHalfByte = (dataLenLo >= 0) ? dataLenLo : (256 + dataLenLo);
        lowHalfByte = highHalfByte & 0xF;
        highHalfByte /= 16;
        str += HEXTABLE[highHalfByte];
        str += HEXTABLE[lowHalfByte];
        
        /** Data (dataLen bytes). */
        for (int i = 0; i < data.length; i++) {
        	highHalfByte = (data[i] >= 0) ? data[i] : 256 + data[i];
        	lowHalfByte = highHalfByte & 0xF;
            highHalfByte /= 16;
            str += HEXTABLE[highHalfByte];
            str += HEXTABLE[lowHalfByte];
        }
        
        return str;
    }

    /** 
     * Converts the packet to a string. This function must undo the effects of 
     * the StealthNetPacket(String) constructor, because this function is used
     * to convert a packet to a string for transmission.
     * 
     * @return A string representing the contents of the packet.
     */
    public String toString() {
        String str = getContents();
        int lowHalfByte, highHalfByte;
        
        /** MAC Digest length (2 bytes) */
        final int digestLenHi = (digest.length / 256);
        final int digestLenLo = (digest.length % 256);
        
        /* First byte */
        highHalfByte = (digestLenHi >= 0) ? digestLenHi : (256 + digestLenHi);
        lowHalfByte = highHalfByte & 0xF;
        highHalfByte /= 16;
        str += HEXTABLE[highHalfByte];
        str += HEXTABLE[lowHalfByte];
        
        /* Second byte */
        highHalfByte = (digestLenLo >= 0) ? digestLenLo : (256 + digestLenLo);
        lowHalfByte = highHalfByte & 0xF;
        highHalfByte /= 16;
        str += HEXTABLE[highHalfByte];
        str += HEXTABLE[lowHalfByte];
        
        /** MAC Digest (digestLen bytes). */
        for (int i = 0; i < digest.length; i++) {
        	highHalfByte = (digest[i] >= 0) ? digest[i] : (256 + digest[i]);
        	lowHalfByte = highHalfByte & 0xF;
            highHalfByte /= 16;
            str += HEXTABLE[highHalfByte];
            str += HEXTABLE[lowHalfByte];
        }

        return str;
    }
    
    /**
     * Verify a MAC digest by calculating our own MAC digest of the same data,
     * and comparing the two. If the StealthNetMAC instance is null, then the
     * verification will pass automatically.
     * 
     * @param mac The StealthNetMAC instance to calculate the MAC digest.
     * @return True if the digest matches (or if the StealthNetMAC instance is
     * null), otherwise false.
     */
    public boolean verifyMAC(StealthNetMAC mac) {
    	if (mac == null)
    		return true;
    	else 
    		return mac.verifyMAC(getContents(), digest);
    }

    /** 
     * A utility function to convert hexadecimal numbers to decimal integers.
     * 
     * @param hex The hexadecimal character to convert to an integer.
     * @return The integer value of the hexadecimal character.
     */
    private static int hexToInt(char hex) {
             if ((hex >= '0') && (hex <= '9')) return (hex - '0');
        else if ((hex >= 'A') && (hex <= 'F')) return (hex - 'A' + 10);
        else if ((hex >= 'a') && (hex <= 'f')) return (hex - 'a' + 10);
        else return 0;
    }
    
    /**
     * Get the name of a command from its byte value. For debug purposes only.
     * 
     * @param command The byte value of the command to query the name of.
     * @return A String containing the name of the command.
     */
    public static String getCommandName(byte command) {
    	switch (command) {
    		case CMD_NULL:
				return "CMD_NULL";
    		case CMD_LOGIN:
    			return "CMD_LOGIN";
    		case CMD_LOGOUT:
    			return "CMD_LOGOUT";
    		case CMD_MSG:
				return "CMD_MSG";
    		case CMD_CHAT:
    			return "CMD_CHAT";
    		case CMD_FTP:
    			return "CMD_FTP";
    		case CMD_LIST:
    			return "CMD_LIST";
    		case CMD_CREATESECRET:
    			return "CMD_CREATESECRET";
    		case CMD_SECRETLIST:
				return "CMD_SECRETLIST";
    		case CMD_GETSECRET:
    			return "CMD_GETSECRET";
    		case CMD_PUBLICKEY:
				return "CMD_PUBLICKEY";
    		case CMD_INTEGRITYKEY:
				return "CMD_INTEGRITYKEY";
			default:
				return "UNKNOWN";
    	}
    }
}

/******************************************************************************
 * END OF FILE:     StealthNetPacket.java
 *****************************************************************************/
