/******************************************************************************
 * ELEC5616/NETS3016
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie and Stephen Gould
 *
 * PROJECT:         StealthNet
 * FILENAME:        StealthNetServer.java
 * AUTHORS:         Matt Barrie and Stephen Gould
 * DESCRIPTION:     Implementation of StealthNet Server for ELEC5616/NETS3016
 *                  programming assignment.
 *                  This code has been written for the purposes of teaching
 *                  cryptography and computer security. It is to be used as
 *                  a demonstration only. No attempt has been made to optimise
 *                  the source code.
 * VERSION:         1.0-ICE
 *
 * REVISION HISTORY:
 *
 *****************************************************************************/

/* Import Libraries **********************************************************/

import java.io.*;
import java.net.*;

/* StealthNetServer Class Definition *****************************************/

public class StealthNetServer {
    public static void main(String[] args) throws IOException {
        ServerSocket svrSocket = null;
        try {
            svrSocket = new ServerSocket(StealthNetComms.SERVERPORT);
        } catch (IOException e) {
            System.err.println("Could not listen on port: " + StealthNetComms.SERVERPORT);
            System.exit(1);
        }

        System.out.println("Server online...");
        while (true) {
            new StealthNetServerThread(svrSocket.accept()).start();
            System.out.println("Server accepted connection...");
        }
    }
}

/******************************************************************************
 * END OF FILE:     StealthNetServer.java
 *****************************************************************************/
 
