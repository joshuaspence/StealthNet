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
 * A class to store the data passed between StealthNet clients.
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
    
    /** Hexadecimal characters. */
    private static final char[] HEXTABLE = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    /** The command being sent in the packet. */
    byte command;      
    
    /** The data being sent in the packet. */
    byte data[];        

    /** Constructor. */
    public StealthNetPacket() {
        command = CMD_NULL;
        data = new byte[0];
    }

    /** 
     * Constructor. 
     *
     * @param cmd The command to be sent in the packet.
     * @param d The data to be sent in the packet.
     */
    public StealthNetPacket(byte cmd, byte[] d) {
        command = cmd;
        if (d == null)
            data = new byte[0];
        else
        	data = d;
    }

    /** 
     * Constructor.
     * 
     * @param str A string consisting of the command to be sent in the packet,
     * as well as the data.
     */
    public StealthNetPacket(String str) {
    	if (str.length() % 2 == 1)
            str = "0" + str;
    	
        if (str.length() == 0) {
            command = CMD_NULL;
            data = new byte[0];
        } else {
            command = (byte) (16 * hexToInt(str.charAt(0)) + hexToInt(str.charAt(1)));
            
            data = new byte[str.length() / 2 - 1];
            for (int i = 0; i < data.length; i++)
                data[i] = (byte) (16 * hexToInt(str.charAt(2 * i + 2)) + hexToInt(str.charAt(2 * i + 3)));
        }
    }

    /** 
     * Converts the packet to a string.
     * 
     * @return A string representing the contents of the packet.
     */
    public String toString() {
        String str;
        int lowByte, highByte;

        str = "";
        highByte = (command >= 0) ? command : 256 + command;
        lowByte = highByte & 15;
        highByte /= 16;
        str += HEXTABLE[highByte];
        str += HEXTABLE[lowByte];
        
        for (int i = 0; i < data.length; i++) {
            highByte = (data[i] >= 0) ? data[i] : 256 + data[i];
            lowByte = highByte & 15;
            highByte /= 16;
            str += HEXTABLE[highByte];
            str += HEXTABLE[lowByte];
        }

        return str;
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
			default:
				return "UNKNOWN";
    	}
    }
}

/******************************************************************************
 * END OF FILE:     StealthNetPacket.java
 *****************************************************************************/
