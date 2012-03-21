/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie and Stephen Gould
 *
 * PROJECT:         StealthNet
 * FILENAME:        StealthNetFileTransfer.java
 * AUTHORS:         Matt Barrie and Stephen Gould
 * DESCRIPTION:     Implementation of StealthNet Client FTP for ELEC5616
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

package StealthNet;

/* Import Libraries **********************************************************/

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import javax.swing.BorderFactory;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JOptionPane;

/* StealthNetFileTransfer Class Definition ************************************/

/**
 * A class to manage a file transfer between multiple StealthNet clients.
 * 
 * @author Matt Barrie
 * @author Stephen Gould
 */
public class StealthNetFileTransfer extends Thread {
	private static final boolean DEBUG = false;
	
    private static final int PACKETSIZE = 256;

    private JProgressBar progressBar = null;
    private StealthNetComms stealthComms = null;
    private String filename;
    private boolean bSend;

    /** Constructor. */
    public StealthNetFileTransfer(StealthNetComms snComms, String fn, boolean b) {
        stealthComms = snComms;
        filename = fn.trim();
        bSend = b;
    }

    /** TODO */
    public Component createGUI() {
        /** Create progress bar. */
        progressBar = new JProgressBar(0, 10);
        progressBar.setValue(0);
        progressBar.setStringPainted(true);

        /** Create top-level panel and add components. */
        JPanel pane = new JPanel();
        pane.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        pane.setLayout(new BorderLayout());
        pane.add(progressBar, BorderLayout.NORTH);

        return pane;
    }

    /** TODO */
    public void run() {
        Dimension screenDim = Toolkit.getDefaultToolkit().getScreenSize();

        /** Set up FTP window */
        JFrame ftpFrame = new JFrame("stealthnet FTP [" + filename + "]");
        ftpFrame.getContentPane().add(createGUI(), BorderLayout.CENTER);
        ftpFrame.pack();

        /** Center the window. */
        int x = (screenDim.width - ftpFrame.getSize().width) / 2;
        int y = (screenDim.height - ftpFrame.getSize().height) / 2;
        ftpFrame.setLocation(x, y);
        ftpFrame.setVisible(true);

        if (bSend)
            sendFile();
        else
            recvFile();

        ftpFrame.setVisible(false);
        JOptionPane.showMessageDialog(ftpFrame,
            (bSend ? "Upload Complete" : "Download Complete"),
            "StealthNet", JOptionPane.INFORMATION_MESSAGE);
    }

    /** TODO */
    private synchronized void sendFile() {
        FileInputStream fid = null;
        byte[] buf = new byte[PACKETSIZE];
        int bufLen;
        int fileLen = (int) ((new File(filename)).length() / PACKETSIZE);

        progressBar.setMaximum(fileLen);
        try {
            stealthComms.sendPacket(StealthNetPacket.CMD_FTP, Integer.toString(fileLen));
            stealthComms.recvPacket();
            fid = new FileInputStream(filename);
            
            do {
                bufLen = fid.read(buf);
                if (bufLen > 0) {
                    stealthComms.sendPacket(StealthNetPacket.CMD_FTP, buf, bufLen);
                    stealthComms.recvPacket();
                }
                progressBar.setValue(progressBar.getValue() + 1);
            } while (bufLen > 0);
            
            fid.close();
            stealthComms.sendPacket(StealthNetPacket.CMD_FTP);
        } catch (IOException e) {
            System.err.println("Error reading from file " + filename);
            if (DEBUG) e.printStackTrace();
        }
    }

    /** TODO */
    private synchronized void recvFile() {
        FileOutputStream fid = null;
        byte[] buf;
        int fileLen;

        try {
            fileLen = (new Integer(new String(stealthComms.recvPacket().data))).intValue();
            stealthComms.sendPacket(StealthNetPacket.CMD_NULL);
            progressBar.setMaximum(fileLen);
            fid = new FileOutputStream(filename);
            
            do {
                buf = stealthComms.recvPacket().data;
                stealthComms.sendPacket(StealthNetPacket.CMD_NULL);
                fid.write(buf);
                progressBar.setValue(progressBar.getValue() + 1);
            } while (buf.length > 0);
            
            fid.close();
        } catch (IOException e) {
            System.err.println("Error writing to file " + filename);
            if (DEBUG) e.printStackTrace();
        }
   }
}

/******************************************************************************
 * END OF FILE:     StealthNetFileTransfer.java
 *****************************************************************************/