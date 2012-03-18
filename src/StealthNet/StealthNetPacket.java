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

public class StealthNetPacket {
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
   
    
    private static final char[] HEXTABLE =
        {'0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    byte command;               // command
    byte data[];                // data

    public StealthNetPacket() {
        command = CMD_NULL;
        data = new byte[0];
    }

    public StealthNetPacket(byte cmd, byte[] d) {
        command = cmd;
        if (d == null)
            data = new byte[0];
        else data = d;
    }

    public StealthNetPacket(String str) {
        int i;

        if (str.length() % 2 == 1)
            str = "0" + str;

        if (str.length() == 0) {
            command = CMD_NULL;
            data = new byte[0];
        } else {
            command = (byte) (16 * hexToInt(str.charAt(0)) + hexToInt(str.charAt(1)));
            data = new byte[str.length() / 2 - 1];
            for (i = 0; i < data.length; i++) {
                data[i] = (byte) (16 * hexToInt(str.charAt(2*i + 2)) + hexToInt(str.charAt(2*i + 3)));
            }
        }
    }

    public String toString() {
        String str;
        int i, lowByte, highByte;

        str = "";
        highByte = (command >= 0) ? command : 256 + command;
        lowByte = highByte & 15;
        highByte /= 16;
        str += HEXTABLE[highByte];
        str += HEXTABLE[lowByte];
        for (i = 0; i < data.length; i++) {
            highByte = (data[i] >= 0) ? data[i] : 256 + data[i];
            lowByte = highByte & 15;
            highByte /= 16;
            str += HEXTABLE[highByte];
            str += HEXTABLE[lowByte];
        }

        return str;
    }

    private static int hexToInt(char hex) {
        if ((hex >= '0') && (hex <= '9')) return (hex - '0');
        if ((hex >= 'A') && (hex <= 'F')) return (hex - 'A' + 10);
        if ((hex >= 'a') && (hex <= 'f')) return (hex - 'a' + 10);
        return 0;
    }
}

/******************************************************************************
 * END OF FILE:     StealthNetPacket.java
 *****************************************************************************/
