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

/* Import Libraries **********************************************************/

import java.io.*;
import javax.swing.*;
import java.awt.*;

/* StealthNetFileTransfer Class Definition ************************************/

public class StealthNetFileTransfer extends Thread {
    private static final int PACKETSIZE = 256;

    private JProgressBar progressBar = null;
    private StealthNetComms stealthComms = null;
    private String filename;
    private boolean bSend;

    public StealthNetFileTransfer(StealthNetComms snComms, String fn, boolean b) {
        stealthComms = snComms;
        filename = fn.trim();
        bSend = b;
    }

    public Component createGUI() {
        // create progress bar
        progressBar = new JProgressBar(0, 10);
        progressBar.setValue(0);
        progressBar.setStringPainted(true);

        // create top-level panel and add components
        JPanel pane = new JPanel();
        pane.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        pane.setLayout(new BorderLayout());
        pane.add(progressBar, BorderLayout.NORTH);

        return pane;
    }

    public void run() {
        Dimension screenDim = Toolkit.getDefaultToolkit().getScreenSize();

        // set up ftp window
        JFrame ftpFrame = new JFrame("stealthnet FTP [" + filename + "]");
        ftpFrame.getContentPane().add(createGUI(), BorderLayout.CENTER);
        ftpFrame.pack();

        // center the window
        int x = (screenDim.width - ftpFrame.getSize().width)/2;
        int y = (screenDim.height - ftpFrame.getSize().height)/2;
        ftpFrame.setLocation(x, y);
        ftpFrame.setVisible(true);

        if (bSend) {
            sendFile();
        } else {
            recvFile();
        }

        ftpFrame.setVisible(false);
        JOptionPane.showMessageDialog(ftpFrame,
            (bSend ? "Upload Complete" : "Download Complete"),
            "StealthNet", JOptionPane.INFORMATION_MESSAGE);
    }

    private synchronized void sendFile() {
        FileInputStream fid = null;
        byte[] buf = new byte[PACKETSIZE];
        int bufLen;
        int fileLen = (int)((new File(filename)).length() / PACKETSIZE);

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
        }
    }

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
        }
   }
}

/******************************************************************************
 * END OF FILE:     StealthNetFileTransfer.java
 *****************************************************************************/
