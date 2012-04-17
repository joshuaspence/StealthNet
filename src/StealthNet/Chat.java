/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet
 * FILENAME:        Chat.java
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

/* StealthNet.Chat Class Definition ******************************************/

/**
 * The chat window used to allow two StealthNet clients to communicate in a 
 * graphical chat window.
 * 
 * @author Matt Barrie
 * @author Joshua Spence
 */
public class Chat extends Thread {
	/** Debug options. */
	private static final boolean DEBUG_GENERAL     = Debug.isDebug("StealthNet.Chat.General");
	private static final boolean DEBUG_ERROR_TRACE = Debug.isDebug("StealthNet.Chat.ErrorTrace") || Debug.isDebug("ErrorTrace");
	
	/** GUI elements. */
	private JFrame chatFrame;
    private JTextArea chatTextBox;
    private JTextField msgText;
    
    /** 
     * The StealthNet communications instance used to allow the clients to 
     * communicate.
     */
    private Comms stealthComms = null;
    
    /** The ID of the user owning the chat session. */
    private final String userID;

    /** 
     * Constructor.
     * 
     * @param id The ID of the user owning the chat session.
     * @param snComms The Comms class used to allow the clients to communicate.
     */
    public Chat(String id, Comms snComms) {
        this.userID = id;
        this.stealthComms = snComms;
    }

    /** 
     * Cleans up before destroying the class.
     * 
     * @throws IOException
     */
    protected void finalize() throws IOException {
        if (stealthComms != null) 
        	stealthComms.terminateSession();
    }

    /** 
     * Creates the GUI for the Chat instance.
     * 
     * @return An AWT component containing the chat elements.
     */
    public Component createGUI() {
        /** Create text window. */
        chatTextBox = new JTextArea();
        chatTextBox.setLineWrap(true);
        chatTextBox.setWrapStyleWord(true);
        chatTextBox.setEditable(false);
        chatTextBox.setBackground(Color.lightGray);
        
        final JScrollPane chatScrollPane = new JScrollPane(chatTextBox);
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
            public void actionPerformed(ActionEvent e) { sendChat(); }
        });
        
        final JButton quitBtn = new JButton("X");
        quitBtn.setVerticalTextPosition(AbstractButton.BOTTOM);
        quitBtn.setHorizontalTextPosition(AbstractButton.CENTER);
        quitBtn.setMnemonic(KeyEvent.VK_Q);
        quitBtn.setToolTipText("Quit");
        quitBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (stealthComms != null) {
                	if (DEBUG_GENERAL) System.out.println("Terminating chat session.");
                    stealthComms.sendPacket(Packet.CMD_LOGOUT);
                    stealthComms.terminateSession();
                }
                stealthComms = null;
            }
        });
        
        final JPanel btnPane = new JPanel();
        btnPane.setLayout(new BorderLayout());
        btnPane.add(msgText);
        btnPane.add(quitBtn, BorderLayout.EAST);

        /** Create top-level panel and add components. */
        final JPanel pane = new JPanel();
        pane.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));
        pane.setLayout(new BorderLayout());
        pane.add(chatScrollPane);
        pane.add(btnPane, BorderLayout.SOUTH);

        return pane;
    }

    /** Send a chat message using StealthNet. */
    private synchronized void sendChat() {
        final String msg = "[" + userID + "] " + msgText.getText();

        chatTextBox.append(msg + "\n");
        if (stealthComms != null) {
        	if (DEBUG_GENERAL) System.out.println("Sending chat message: \"" + msg + "\".");
            stealthComms.sendPacket(Packet.CMD_MSG, msg);
        }
        msgText.setText("");
    }

    /** Receive a chat message using StealthNet. */
    private synchronized void recvChat() {
        try {
            if ((stealthComms == null) || (!stealthComms.recvReady()))
                return;
        } catch (IOException e) {
            if (stealthComms != null) {
                stealthComms.sendPacket(Packet.CMD_LOGOUT);
                stealthComms.terminateSession();
            }
            stealthComms = null;
            return;
        }

        Packet pckt = new Packet();
        try {
            while ((pckt.command != Packet.CMD_LOGOUT) && (stealthComms.recvReady())) {
                pckt = stealthComms.recvPacket();
                
                if (pckt == null)
                	break;
                
                switch (pckt.command) {                
                    case Packet.CMD_MSG:
                    	/** Chat message received. */
                    	final String msg = new String(pckt.data);
                    	if (DEBUG_GENERAL) System.out.println("Received chat message: \"" + msg + "\".");
                	    chatTextBox.append(msg + "\n");
                        break;
                        
                    case Packet.CMD_LOGOUT:
                    	/** Terminate chat session. */
                    	if (DEBUG_GENERAL) System.out.println("Terminating chat session.");
                        JOptionPane.showMessageDialog(chatFrame,
                            "Chat session terminated at other side.",
                            "StealthNet", JOptionPane.INFORMATION_MESSAGE);
                        stealthComms.terminateSession();
                        stealthComms = null;
                        break;
                        
                    default:
                        System.err.println("Unrecognised command.");
               }
            }
        } catch (Exception e) {
            System.err.println("Error running chat thread.");
            if (DEBUG_ERROR_TRACE) e.printStackTrace();
        }
    }

    /** The main function for Chat. */
    public void run() {
        final Dimension screenDim = Toolkit.getDefaultToolkit().getScreenSize();

        /** Set up chat window. */
        chatFrame = new JFrame("stealthnet chat [" + userID + "]");
        chatFrame.getContentPane().add(createGUI(), BorderLayout.CENTER);
        chatFrame.pack();
        msgText.requestFocus();

        chatFrame.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                if (stealthComms != null) {
                    stealthComms.sendPacket(Packet.CMD_LOGOUT);
                    stealthComms.terminateSession();
                }
                stealthComms = null;
            }
        });

        /** Centre the window. */
        final int x = (screenDim.width - chatFrame.getSize().width) / 2;
        final int y = (screenDim.height - chatFrame.getSize().height) / 2;
        chatFrame.setLocation(x, y);
        chatFrame.setVisible(true);

        /** Wait for chat messages. */
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
 * END OF FILE:     Chat.java
 *****************************************************************************/