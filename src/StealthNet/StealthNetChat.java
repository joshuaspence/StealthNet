/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PROJECT:         StealthNet
 * FILENAME:        StealthNetChat.java
 * AUTHORS:         Matt Barrie
 * DESCRIPTION:     Implementation of StealthNet Client Chat for ELEC5616
 *                  programming assignment.
 *                  This code has been written for the purposes of teaching
 *                  cryptography and computer security. It is to be used as
 *                  a demonstration only. No attempt has been made to optimise
 *                  the source code.
 * VERSION:         2.0-ICE
 *
 *****************************************************************************/

package StealthNet;

/* Import Libraries **********************************************************/

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import javax.swing.AbstractButton;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

/* StealthNetChat Class Definition *******************************************/

/**
 * TODO
 * 
 * @author Matt Barrie
 */
public class StealthNetChat extends Thread {
	private static final boolean DEBUG = false;
	
    private JFrame chatFrame;
    private JTextArea chatTextBox;
    private JTextField msgText;
    private StealthNetComms stealthComms = null;
    private String userID;

    /** Constructor. */
    public StealthNetChat(String id, StealthNetComms snComms) {
        userID = id;
        stealthComms = snComms;
    }

    /** Cleans up before destroying the class. */
    protected void finalize() throws IOException {
        if (stealthComms != null) stealthComms.terminateSession();
    }

    /** TODO */
    public Component createGUI() {
        /** Create text window. */
        chatTextBox = new JTextArea();
        chatTextBox.setLineWrap(true);
        chatTextBox.setWrapStyleWord(true);
        chatTextBox.setEditable(false);
        chatTextBox.setBackground(Color.lightGray);
        
        JScrollPane chatScrollPane = new JScrollPane(chatTextBox);
        chatScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        chatScrollPane.setPreferredSize(new Dimension(280, 100));
        chatScrollPane.setBorder(
            BorderFactory.createCompoundBorder(
                BorderFactory.createCompoundBorder(
                    BorderFactory.createTitledBorder("Chat"),
                    BorderFactory.createEmptyBorder(0,0,0,0)),
                chatScrollPane.getBorder()));

        /** Create text input field (and quit button). */
        msgText = new JTextField(25);
        msgText.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                sendChat();
            }
        });
        
        final JButton quitBtn = new JButton("X");
        quitBtn.setVerticalTextPosition(AbstractButton.BOTTOM);
        quitBtn.setHorizontalTextPosition(AbstractButton.CENTER);
        quitBtn.setMnemonic(KeyEvent.VK_Q);
        quitBtn.setToolTipText("Quit");
        quitBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (stealthComms != null) {
                    stealthComms.sendPacket(StealthNetPacket.CMD_LOGOUT);
                    stealthComms.terminateSession();
                }
                stealthComms = null;
            }
        });
        
        JPanel btnPane = new JPanel();
        btnPane.setLayout(new BorderLayout());
        btnPane.add(msgText);
        btnPane.add(quitBtn, BorderLayout.EAST);

        /** Create top-level panel and add components. */
        JPanel pane = new JPanel();
        pane.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));
        pane.setLayout(new BorderLayout());
        pane.add(chatScrollPane);
        pane.add(btnPane, BorderLayout.SOUTH);

        return pane;
    }

    /** TODO */
    private synchronized void sendChat() {
        String msg = "[" + userID + "] " + msgText.getText();

        chatTextBox.append(msg + "\n");
        if (stealthComms != null)
            stealthComms.sendPacket(StealthNetPacket.CMD_MSG, msg);
        msgText.setText("");
    }

    private synchronized void recvChat() {
        try {
            if ((stealthComms == null) || (!stealthComms.recvReady()))
                return;
        } catch (IOException e) {
            if (stealthComms != null) {
                stealthComms.sendPacket(StealthNetPacket.CMD_LOGOUT);
                stealthComms.terminateSession();
            }
            stealthComms = null;
            return;
        }

        StealthNetPacket pckt = new StealthNetPacket();

        try {
            while ((pckt.command != StealthNetPacket.CMD_LOGOUT) && (stealthComms.recvReady())) {
                pckt = stealthComms.recvPacket();
                
                switch (pckt.command) {
                    case StealthNetPacket.CMD_MSG:
                	    chatTextBox.append(new String(pckt.data) + "\n");
                        break;
                        
                    case StealthNetPacket.CMD_LOGOUT:
                        JOptionPane.showMessageDialog(chatFrame,
                            "Chat session terminated at other side.",
                            "StealthNet", JOptionPane.INFORMATION_MESSAGE);
                        stealthComms.terminateSession();
                        stealthComms = null;
                        break;
                        
                    default:
                        System.out.println("Unrecognised command.");
               }
            }
        } catch (Exception e) {
            System.err.println("Error running client thread.");
            e.printStackTrace();
        }
    }

    /** TODO */
    public void run() {
        Dimension screenDim = Toolkit.getDefaultToolkit().getScreenSize();

        /** Set up chat window. */
        chatFrame = new JFrame("stealthnet chat [" + userID + "]");
        chatFrame.getContentPane().add(createGUI(), BorderLayout.CENTER);
        chatFrame.pack();
        msgText.requestFocus();

        chatFrame.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                if (stealthComms != null) {
                    stealthComms.sendPacket(StealthNetPacket.CMD_LOGOUT);
                    stealthComms.terminateSession();
                }
                stealthComms = null;
            }
        });

        /** Center the window. */
        int x = (screenDim.width - chatFrame.getSize().width) / 2;
        int y = (screenDim.height - chatFrame.getSize().height) / 2;
        chatFrame.setLocation(x, y);
        chatFrame.setVisible(true);

        while (stealthComms != null) {
            recvChat();
            try {
                sleep(100);
            } catch (Exception e) {}
        }

        chatTextBox = null;
        msgText = null;
        chatFrame.setVisible(false);
    }
}

/******************************************************************************
 * END OF FILE:     StealthNetChat.java
 *****************************************************************************/
