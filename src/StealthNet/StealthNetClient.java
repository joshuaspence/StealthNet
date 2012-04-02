/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie, Stephen Gould and Ryan Junee
 *
 * PROJECT:         StealthNet
 * FILENAME:        StealthNetClient.java
 * AUTHORS:         Matt Barrie, Stephen Gould and Ryan Junee
 * DESCRIPTION:     Implementation of StealthNet Client for ELEC5616
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

import java.awt.Component;
import java.awt.Dimension;
import java.awt.FileDialog;
import java.awt.GridLayout;
import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.MouseAdapter;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.util.Hashtable;
import javax.swing.AbstractButton;
import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.JOptionPane;

/* StealthNetClient Class Definition *****************************************/

/** 
 * A client for the StealthNet chat program. Receives information about clients 
 * and secrets from the StealthNet server.
 * 
 * If the client wants to start a chat session with a user, then the first 
 * client sends a command to the server, containing an IP address and port 
 * number on which the first client is waiting for a connection from the second
 * client. The server relays this information to the second client, which should
 * then connect with the first client to start the chat session.
 * 
 * Similarly, if the clients wants to send a file to another client, then the
 * first clients send a command to the server, containing an IP address and port
 * number on which the first client is waiting for a connection from the second 
 * client. The server relays this information to the second client, which should
 * then connect with the first client to start the file transfer.
 * 
 * @author Matt Barrie
 * @author Stephen Gould
 * @author Ryan Junee
 */
public class StealthNetClient {
	/** 
	 * Set to true in build.xml to output debug messages for this class. 
	 * Alternatively, use the argument `-Ddebug.StealthNetComms=true' at the 
	 * command line. 
	 */
	private static final boolean DEBUG = (System.getProperty("debug.StealthNetClient", "false").equals("true"));
	
	/** StealthNet server (defaults to StealthNetComms.DEFAULT_SERVERNAME). */
	private final String server_hostname;
	
	/** StealthNet port (defaults to StealthNetComms.DEFAULT_SERVERNAME). */
	private final int server_port;
	
	/** The main frame for this client. */
    private static JFrame clientFrame;
    
    /** A text box used to display messages to the user. */
    private JTextArea msgTextBox;
    
    /** Button to log into StealthNet. */
    private JButton loginBtn;
    
    /** Used for communications with the StealthNet server. */
    private StealthNetComms stealthComms = null;
    
    /** A timer to periodically process incoming packets. */
    private final Timer stealthTimer;
    
    /** The ID of this (client) user. */
    private String userID = null;
    
    /** Buddy list. */
    private JTable buddyTable = null;
    private DefaultTableModel buddyListData = null;
    
    /** Secret list. */
    private DefaultTableModel secretListData = null;
    
    /** Graphical representation of the secret list. */
    private JTable secretTable = null;
    
    /** Field to show the remaining number of credits. */
	JTextField creditsBox;
	
	/** Give them 100 credits for demonstration purposes. */
    private int credits = 100;

    /** Secret data. */
	private class SecretData {
		String description = null;
		String filename = null;
	}

	/** A list of secret data, indexed by secret name. */
	static private Hashtable<String, SecretData> secretDescriptions = new Hashtable<String, SecretData>();
    
    /** Constructor. */
    public StealthNetClient() {
    	/** Create a timer to process packets every 100ms. */
        stealthTimer = new Timer(100, new ActionListener() {
            public void actionPerformed(ActionEvent e) { processPackets(); }
        });
        
        server_hostname = StealthNetComms.DEFAULT_SERVERNAME;
        server_port = StealthNetComms.DEFAULT_SERVERPORT;
    }

    /** 
	 * Constructor. 
	 * 
	 * @param s The hostname of the StealthNet server.
	 * @param p The port that the StealthNet server is listening on.
	 * 
	 * @throws NoSuchAlgorithmException
	 */
    public StealthNetClient(String s, int p)  {    	
    	/** Create a timer to process packets every 100ms. */
        stealthTimer = new Timer(100, new ActionListener() {
            public void actionPerformed(ActionEvent e) { processPackets(); }
        });
        
        server_hostname = s;
        server_port = p;
    }
    
    /**
     * Create the GUI for the client instance.
     * 
     * @return An AWT component containing the client GUI.
     */
    @SuppressWarnings("serial")
	public Component createGUI() {
        final JPanel pane = new JPanel();
            	
        /** Create user list. */
        buddyListData = new DefaultTableModel() {
        	public boolean isCellEditable(int row, int col) { return false; };
        };
        buddyListData.addColumn("User ID");
        buddyListData.addColumn("Online");
        buddyTable = new JTable(buddyListData);
        buddyTable.setPreferredScrollableViewportSize(new Dimension(200, 100));
        buddyTable.getColumnModel().getColumn(0).setPreferredWidth(180);
        
        final JScrollPane buddyScrollPane = new JScrollPane(buddyTable);
        buddyScrollPane.setBorder(
            BorderFactory.createCompoundBorder(
                BorderFactory.createCompoundBorder(
                    BorderFactory.createTitledBorder("User List"),
                    BorderFactory.createEmptyBorder(0,0,0,0)),
                buddyScrollPane.getBorder()));
               
        /** Add mouse listen for popup windows. Act on JTable row right-click. */
		MouseListener ml = new MouseAdapter() {
			JPopupMenu popup;
			int row;
			
			public void mousePressed(MouseEvent e) {
				if (SwingUtilities.isRightMouseButton(e)) mouseReleased(e);
			}

			public void mouseClicked(MouseEvent e) {
			    if (SwingUtilities.isRightMouseButton(e)) mouseReleased(e);
			}
			
			public void mouseReleased(MouseEvent e) {	
				if (e.isShiftDown() || e.isControlDown() || e.isAltDown())
       				return;
      			
				if (e.isPopupTrigger()) {
      				JMenuItem item;
      				
           			row = buddyTable.rowAtPoint(e.getPoint());	
        								
					popup = new JPopupMenu("Action");
					popup.setLabel("Action");
					
					item = new JMenuItem("Chat");
					item.addActionListener(new ActionListener() {
        		 	   public void actionPerformed(ActionEvent e) { startChat(row); }
        			});
					popup.add(item);
					
					item = new JMenuItem("Send File");
					item.addActionListener(new ActionListener() {
        		 	   public void actionPerformed(ActionEvent e) { sendFile(row); }
        			});
        			popup.add(item);
        			
        			popup.show(e.getComponent(),e.getX(), e.getY());
      			}
    		}
  		};
  		buddyTable.addMouseListener(ml);

        /** Create secret window. */
        secretListData = new DefaultTableModel() {
        	public boolean isCellEditable(int row, int col) { return false;	};
        };
        secretListData.addColumn("Secret");
        secretListData.addColumn("Cost");
        
        secretTable = new JTable(secretListData);
        secretTable.setPreferredScrollableViewportSize(new Dimension(200, 100));
        secretTable.getColumnModel().getColumn(0).setPreferredWidth(180);
        
		ml = new MouseAdapter() {
			JPopupMenu popup;
			int row;
			
			public void mousePressed(MouseEvent e) {
				if (SwingUtilities.isRightMouseButton(e)) mouseReleased(e);
			}

			public void mouseClicked(MouseEvent e) {
			    if (SwingUtilities.isRightMouseButton(e)) mouseReleased(e);
			}
			
			public void mouseReleased(MouseEvent e) {
				if (e.isShiftDown() || e.isControlDown() || e.isAltDown())
       				return;
      			
				if (e.isPopupTrigger()) {
        			JMenuItem item;
        			
        			row = buddyTable.rowAtPoint(e.getPoint());	
        								
					popup = new JPopupMenu("Action");
					popup.setLabel("Action");
					
					item = new JMenuItem("Details");
					item.addActionListener(new ActionListener() {
						public void actionPerformed(ActionEvent e) { secretDetails(row); }
					});
					popup.add(item);
					
					item = new JMenuItem("Purchase");
			        item.addActionListener(new ActionListener() {
        		 	   public void actionPerformed(ActionEvent e) { purchaseSecret(row); }
        			});
    				popup.add(item);
					
        			popup.show(e.getComponent(),e.getX(), e.getY());
      			}
    		}
  		};
  		secretTable.addMouseListener(ml);
        
        final JScrollPane secretScrollPane = new JScrollPane(secretTable);
        secretScrollPane.setBorder(
            BorderFactory.createCompoundBorder(
                BorderFactory.createCompoundBorder(
                    BorderFactory.createTitledBorder("Secrets List"),
                    BorderFactory.createEmptyBorder(0,0,0,0)),
                secretScrollPane.getBorder()));

        /** Create instant message window. */
        msgTextBox = new JTextArea("Authentication required.\n");
        msgTextBox.setLineWrap(true);
        msgTextBox.setWrapStyleWord(true);
        msgTextBox.setEditable(false);
        final JScrollPane msgScrollPane = new JScrollPane(msgTextBox);
        msgScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        msgScrollPane.setPreferredSize(new Dimension(200, 100));
        msgScrollPane.setBorder(
            BorderFactory.createCompoundBorder(
                BorderFactory.createCompoundBorder(
                    BorderFactory.createTitledBorder("Console"),
                    BorderFactory.createEmptyBorder(0,0,0,0)),
                msgScrollPane.getBorder()));

        /** Create split pane for buddy list and messages. */
        final JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, buddyScrollPane, secretScrollPane);
        splitPane.setOneTouchExpandable(true);
        splitPane.setDividerLocation(150);

		final JSplitPane topPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, splitPane, msgScrollPane);
        topPane.setOneTouchExpandable(true);  

		/** Credits display. */
		final JPanel creditsPane = new JPanel();
		creditsPane.setLayout(new GridLayout(1, 0));
		creditsPane.setPreferredSize(new Dimension(180, 30));
		creditsPane.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
		creditsPane.add(new JLabel("Credits:  ", SwingConstants.RIGHT));
		creditsBox = new JTextField(new Integer(credits).toString());
		creditsBox.setEditable(false);
		creditsPane.add(creditsBox);
                
        /** Create buttons (login, send message, chat, ftp) */
        loginBtn = new JButton(new ImageIcon(this.getClass().getClassLoader().getResource("img/login.gif")));
        loginBtn.setVerticalTextPosition(AbstractButton.BOTTOM);
        loginBtn.setHorizontalTextPosition(AbstractButton.CENTER);
        loginBtn.setMnemonic(KeyEvent.VK_N);
        loginBtn.setToolTipText("Login");
        loginBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (stealthComms == null) { login(); } else { logout(); }
            }
        });

        final JButton msgBtn = new JButton(new ImageIcon(this.getClass().getClassLoader().getResource("img/msg.gif")));
        msgBtn.setVerticalTextPosition(AbstractButton.BOTTOM);
        msgBtn.setHorizontalTextPosition(AbstractButton.CENTER);
        msgBtn.setMnemonic(KeyEvent.VK_M);
        msgBtn.setToolTipText("Create Secret");
        msgBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) { createSecret(); }
        });

        final JPanel btnPane = new JPanel();
        btnPane.setLayout(new GridLayout(1, 0));
        btnPane.setPreferredSize(new Dimension(180, 40));
        btnPane.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
        btnPane.add(loginBtn);
        btnPane.add(msgBtn);

		final JPanel bottomPane = new JPanel();
		bottomPane.setLayout(new BorderLayout());
		bottomPane.add(creditsPane, BorderLayout.NORTH);
		bottomPane.add(btnPane, BorderLayout.SOUTH);

        /** Create top-level panel and add components. */
        pane.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));
        pane.setLayout(new BorderLayout());
        pane.add(topPane, BorderLayout.NORTH);
        pane.add(bottomPane, BorderLayout.SOUTH);

        return pane;
    }

    /** Login to StealthNet. */
    private synchronized void login() {
    	if (DEBUG) System.out.println("Logging in to StealthNet.");
    	
        if (stealthComms != null) {
        	System.err.println("Already logged in!");
        	msgTextBox.append("[*ERR*] Already logged in.\n");
            return;
        }

        try {
        	/** Get the user ID. */
            userID = JOptionPane.showInputDialog("Login:", userID);
            if (userID == null) 
            	return;
            
            /** Initiate a connection with the StealthNet server. */
            stealthComms = new StealthNetComms();
            stealthComms.initiateSession(new Socket(server_hostname, server_port));
            
            /** Send the server a login command. */
            stealthComms.sendPacket(StealthNetPacket.CMD_LOGIN, userID);
            
            /** Start periodically checking for packets. */
            stealthTimer.start();
        } catch (UnknownHostException e) {
        	System.err.println("Unknown host for StealthNet server: " + server_hostname + ".");
            msgTextBox.append("[*ERR*] Unknown host: " + server_hostname + "\n");
            if (DEBUG) e.printStackTrace();
        } catch (IOException e) {
        	System.err.println("Could not connect to StealthNet server on port " + server_port + ".");
            msgTextBox.append("[*ERR*] Could not connect to host: " + server_port + "\n");
            if (DEBUG) e.printStackTrace();
        }
        
        /** We should now be connected to the StealthNet server. */

		msgTextBox.append("Connected to StealthNet.\n");
		if (DEBUG) System.out.println("Connected to StealthNet.");
		
		/** Set the frame title. */
		clientFrame.setTitle("stealthnet [" + userID + "]");
		
		/** Change the login button to a logout button. */
        loginBtn.setIcon(new ImageIcon(this.getClass().getClassLoader().getResource("img/logout.gif")));
        loginBtn.setToolTipText("Logout");
    }

    /** Logout of StealthNet. */
    private synchronized void logout() {
    	if (DEBUG) System.out.println("Logging out of StealthNet.");
    	
        if (stealthComms != null) {
        	/** Stop periodically checking for packets. */
            stealthTimer.stop();
            
            /** Send the server a logout command. */
            stealthComms.sendPacket(StealthNetPacket.CMD_LOGOUT);
            
            /** Terminate session. */
            stealthComms.terminateSession();
            stealthComms = null;
            
            /** Change the logout button back to a login button. */
            loginBtn.setIcon(new ImageIcon(this.getClass().getClassLoader().getResource("img/login.gif")));
            loginBtn.setToolTipText("Login");
            
            /** Hide user and secret list. */
            buddyListData.setRowCount(0);
            secretListData.setRowCount(0);
            
            msgTextBox.append("Disconnected.\n");
            if (DEBUG) System.out.println("Disconnected.");
        }
    }

    /** Create a secret. */
	private void createSecret() {
		if (DEBUG) System.out.println("Creating secret.");
		
    	if (stealthComms == null) {
            msgTextBox.append("[*ERR*] Not logged in.\n");
        } else {
        	String name = "", description = "", cost = "";
        	
        	/** Prompt the user for the secret name, description and cost. */
			name = JOptionPane.showInputDialog("Secret Name:", name);
			description = JOptionPane.showInputDialog("Secret Description:", description);
			cost = JOptionPane.showInputDialog("Secret Cost (credits):", cost);
	
			/** Prompt the user for the secret file. */
	        final FileDialog fileOpen = new FileDialog(clientFrame, "Select Secret File....", FileDialog.LOAD);
	        fileOpen.setVisible(true);
	        if (fileOpen.getFile().length() == 0)
	        	return;
			
			final String userMsg = name + ";" + description + ";" + cost + ";" + fileOpen.getDirectory() + ";" + fileOpen.getFile();
	        if (userMsg != null)
	        	/** Create the secret on the server. */
	        	if (DEBUG) System.out.println("Sending secret details to server. Secret name is \"" + name + "\". Secret cost is " + cost + ". Secret description is \"" + description + "\". Secret file is \"" + fileOpen.getDirectory() + fileOpen.getFile() + "\".");
	        	stealthComms.sendPacket(StealthNetPacket.CMD_CREATESECRET, userMsg);
        }
    }

    /** 
     * Display details of a secret.
     * 
     * @param row The row of the secret to be displayed.
     */
	private void secretDetails(int row) {
		final String name = (String) secretTable.getValueAt(row,0);
		final SecretData data = (SecretData) secretDescriptions.get(name);
		if (data != null)
			JOptionPane.showMessageDialog(null, data.description, "Details of Secret: " + name, JOptionPane.PLAIN_MESSAGE);
	}

	/** 
     * Purchase the details of a secret.
     * 
     * @param row The secret to be purchased.
     */
    private void purchaseSecret(int row) {
		final String name = (String) secretTable.getValueAt(row, 0);
		final SecretData data = secretDescriptions.get(name);
		
		if (DEBUG) System.out.println("Attempting to purchase secret \"" + name + "\".");
		
		if (data == null)
			return;

		/** Set up socket on a free port for file transfer of the secret file. */
		ServerSocket ftpSocket = null;
		try {
			ftpSocket = new ServerSocket(0);
		} catch (IOException e) {
			System.err.println("Could not set up listening port for file transfer.");
			msgTextBox.append("[*ERR*] Transfer failed.\n");
			if (DEBUG) e.printStackTrace();
			return;
		}
		
		if (DEBUG) System.out.println("Set up socket " + ftpSocket.getLocalPort() + " for transfer of secret file \"" + name + "\".");

		/** Discover the IP address of this client. */
		String iAddr;
		try {
			iAddr = InetAddress.getLocalHost().toString();
			if (iAddr.lastIndexOf("/") > 0)
				iAddr = iAddr.substring(0, iAddr.lastIndexOf("/"));
		} catch (UnknownHostException e) {
			iAddr = "localhost";
		}
		iAddr += ":" + Integer.toString(ftpSocket.getLocalPort());
		
		/** 
		 * Send the server the name of the secret and the IP address and port 
		 * number for the file transfer. 
		 */
		if (DEBUG) System.out.println("Sending get secret message to server. Target client should connect on " + iAddr + ":" + ftpSocket.getLocalPort() + ".");
		stealthComms.sendPacket(StealthNetPacket.CMD_GETSECRET, name + "@" + iAddr);

		/** Choose where to save the secret file. */
		final FileDialog fileSave = new FileDialog(clientFrame, "Save As...", FileDialog.SAVE);
		fileSave.setFile(data.filename);
		fileSave.setVisible(true);
		
		if (DEBUG) System.out.println("Will save secret file \"" + name + "\" to \"" + fileSave.getDirectory() + fileSave.getFile() + "\".");
		
		if ((fileSave.getFile() != null) && (fileSave.getFile().length() > 0)) {
			/** Wait for user to connect, then start file transfer. */
			try {
				if (DEBUG) System.out.println("Waiting for target client to connect.");
				
				Socket conn;
				ftpSocket.setSoTimeout(2000);  // 2 second timeout
				final StealthNetComms snComms = new StealthNetComms();
				snComms.acceptSession(conn = ftpSocket.accept());
				
				if (DEBUG) System.out.println("Accepted connection from " + conn.getInetAddress() + ":" + conn.getPort() + " for chat session.");
				new StealthNetFileTransfer(snComms, fileSave.getDirectory() + fileSave.getFile(), false).start();
			} catch (Exception e) {
				System.err.println("Transfer failed.");
				msgTextBox.append("[*ERR*] Transfer failed.\n");
				if (DEBUG) e.printStackTrace();
			}	
		}
    }    

    /** 
     * 
     * Check if we are able to send a message to a specified user.
     * 
     * @param row The user to check.
     */
	private boolean isOKtoSendtoRow(int row) {
		String myid, mystatus;

		myid = (String) buddyTable.getValueAt(row, 0);
		mystatus = (String) buddyTable.getValueAt(row,1);

		if (myid.equals(userID)) {
			System.err.println("Can't send to self.");
		   	msgTextBox.append("[*ERR*] Can't send to self.\n");
		   	return false;
		}

        /** Check if the user is logged in. */
        if (mystatus.equals("false")) {
        	System.err.println("User \"" + myid + "\" is not online.");
        	msgTextBox.append("[*ERR*] User is not online.\n");
        	return false;
        }
        
        return true;
	}
	
	/** 
	 * Start a chat session with the selected user. 
	 *
	 * @param row The user to chat with.
	 */
	private void startChat(int row) {
		if (!isOKtoSendtoRow(row))
			return;
        
		/** Get the ID of the target user. */ 
        String myid = (String) buddyTable.getValueAt(row, 0);
        		
        /** Set up socket on a free port for the chat session. */
        ServerSocket chatSocket = null;

        try {
            chatSocket = new ServerSocket(0);
        } catch (IOException e) {
        	System.err.println("Chat failed. Failed to create ServerSocket.");
            msgTextBox.append("[*ERR*] Chat failed.\n");
            if (DEBUG) e.printStackTrace();
            return;
        }
        
        if (DEBUG) System.out.println("Set up socket " + chatSocket.getLocalPort() + " for chat session with \"" + myid + "\".");

        /**
         * Send message to server with target user and listening address and
         * port for the chat session.
         */
        String iAddr;
        try {
            iAddr = InetAddress.getLocalHost().toString();
            if (iAddr.lastIndexOf("/") > 0)
                iAddr = iAddr.substring(0, iAddr.lastIndexOf("/"));
        } catch (UnknownHostException e) {
            iAddr = "localhost";
        }
        iAddr += ":" + Integer.toString(chatSocket.getLocalPort());
        
        if (DEBUG) System.out.println("Sending chat message to server. Target client should connect on " + iAddr + ":" + chatSocket.getLocalPort() + ".");
        stealthComms.sendPacket(StealthNetPacket.CMD_CHAT, myid + "@" + iAddr);

        /** Wait for user to connect and open chat window. */
        try {
        	if (DEBUG) System.out.println("Waiting for target client to connect.");
        	
        	Socket conn;
            chatSocket.setSoTimeout(2000);  // 2 second timeout
            StealthNetComms snComms = new StealthNetComms();
            snComms.acceptSession(conn = chatSocket.accept());
            
            if (DEBUG) System.out.println("Accepted connection from " + conn.getInetAddress() + ":" + conn.getPort() + " for chat session.");
            new StealthNetChat(userID, snComms).start();
        } catch (Exception e) {
        	System.err.println("Chat failed.");
            msgTextBox.append("[*ERR*] Chat failed.\n");
        }
    }
   
	/** 
	 * Send a file to the selected user.
	 * 
	 * @param row The user to send the file to.
	 */
    private void sendFile(int row) {
		if (!isOKtoSendtoRow(row)) {
			return;
		}
		
		/** Get the user ID. */
		String myid = (String) buddyTable.getValueAt(row, 0);

		/** Select the file to send. */
        FileDialog fileOpen = new FileDialog(clientFrame, "Open...", FileDialog.LOAD);
        fileOpen.setVisible(true);
        if (fileOpen.getFile().length() == 0)
            return;

        /** Set up socket on a free port. */
        ServerSocket ftpSocket = null;
        try {
            ftpSocket = new ServerSocket(0);
        } catch (IOException e) {
            System.err.println("Could not set up listening port.");
            msgTextBox.append("[*ERR*] FTP failed.\n");
            if (DEBUG) e.printStackTrace();
            return;
        }

        if (DEBUG) System.out.println("Set up socket " + ftpSocket.getLocalPort() + " for transfer of file \"" + fileOpen.getFile() + "\" to \"" + myid + "\".");
        
        /**
         * Send message to server with target user and listening address and 
         * port for file transfer.
         */
        String iAddr;
        try {
            iAddr = InetAddress.getLocalHost().toString();
            if (iAddr.lastIndexOf("/") > 0)
                iAddr = iAddr.substring(0, iAddr.lastIndexOf("/"));
        } catch (UnknownHostException e) {
            iAddr = "localhost";
        }
        iAddr += ":" + Integer.toString(ftpSocket.getLocalPort());
        
        if (DEBUG) System.out.println("Sending FTP message to server. Target client should connect on " + iAddr + ":" + ftpSocket.getLocalPort() + ".");
        stealthComms.sendPacket(StealthNetPacket.CMD_FTP, myid + "@" + iAddr + "#" + fileOpen.getFile());

        /** Wait for user to connect, then start file transfer. */
        try {
        	if (DEBUG) System.out.println("Waiting for target client to connect.");
        	
        	Socket conn;
            ftpSocket.setSoTimeout(2000);  // 2 second timeout
            StealthNetComms snComms = new StealthNetComms();
            snComms.acceptSession(conn = ftpSocket.accept());
            
            if (DEBUG) System.out.println("Accepted connection from " + conn.getInetAddress() + ":" + conn.getPort() + " for chat session.");
            new StealthNetFileTransfer(snComms, fileOpen.getDirectory() + fileOpen.getFile(), true).start();
        } catch (Exception e) {
        	System.err.println("FTP failed.");
            msgTextBox.append("[*ERR*] FTP failed.\n");
            if (DEBUG) e.printStackTrace();
        }
    }

    /** Process incoming packets. */
    private void processPackets() {
		/** Update credits box, stick it here for convenience. */
		creditsBox.setText(new Integer(credits).toString());
 
        try {
            if ((stealthComms == null) || (!stealthComms.recvReady()))
                return;
        } catch (IOException e) {
        	System.err.println("The server appears to be down.");
			msgTextBox.append("[*ERR*] The server appears to be down.\n");
			if (DEBUG) e.printStackTrace();
            return;
        }

        String iAddr, fName;
        Integer iPort;
        StealthNetComms snComms;
        StealthNetPacket pckt = new StealthNetPacket();

        /** No need to process packets while we are already processing packets. */
        stealthTimer.stop();

        try {
            /** Check for message from server. */
            while (stealthComms.recvReady()) {
                pckt = stealthComms.recvPacket();
                
                switch (pckt.command) {
                    case StealthNetPacket.CMD_MSG:
                    	final String msg = new String(pckt.data);
                    	if (DEBUG) System.out.println("Received a message command from server. Packet data: \"" + msg + "\".");
                	    msgTextBox.append(msg + "\n");
                        break;

                    case StealthNetPacket.CMD_CHAT:                    	
                        iAddr = new String(pckt.data);
                        iAddr = iAddr.substring(iAddr.lastIndexOf("@") + 1);
                        iPort = new Integer(iAddr.substring(iAddr.lastIndexOf(":") + 1));
                        iAddr = iAddr.substring(0, iAddr.lastIndexOf(":"));
                        
                        if (DEBUG) System.out.println("Received a chat command from server. Target host: " + iAddr + ":" + iPort + ".");
                        
                        snComms = new StealthNetComms();
                        snComms.initiateSession(new Socket(iAddr, iPort.intValue()));
                        if (DEBUG) System.out.println("Opened a communications session with " + iAddr + ".");
                        
                        
                        new StealthNetChat(userID, snComms).start();
                        if (DEBUG) System.out.println("Started a chat session with " + iAddr + ".");
                        break;

                    case StealthNetPacket.CMD_FTP:                    	
                        iAddr = new String(pckt.data);
                        iAddr = iAddr.substring(iAddr.lastIndexOf("@") + 1);
                        fName = iAddr.substring(iAddr.lastIndexOf("#") + 1);
                        iAddr = iAddr.substring(0, iAddr.lastIndexOf("#"));
                        iPort = new Integer(iAddr.substring(iAddr.lastIndexOf(":") + 1));
                        iAddr = iAddr.substring(0, iAddr.lastIndexOf(":"));
                        
                        if (DEBUG) System.out.println("Received a file transfer command from server. Target host: " + iAddr + ":" + iPort + ".");

                        snComms = new StealthNetComms();
                        snComms.initiateSession(new Socket(iAddr, iPort.intValue()));
                        if (DEBUG) System.out.println("Opened a communications session with " + iAddr + ".");
                        
                        final FileDialog fileSave = new FileDialog(clientFrame, "Save As...", FileDialog.SAVE);
                        fileSave.setFile(fName);
                        fileSave.setVisible(true);
                        if ((fileSave.getFile() != null) && (fileSave.getFile().length() > 0)) {
                        	if (DEBUG) System.out.println("File will be saved to \"" + fileSave.getDirectory() + fileSave.getFile() + "\". Starting file transfer.");
                        	
                            new StealthNetFileTransfer(snComms, fileSave.getDirectory() + fileSave.getFile(), false).start();
                        }
                        break;

                    case StealthNetPacket.CMD_LIST:                    	
                        String userTable = new String(pckt.data);
                        buddyListData.setRowCount(0);
                        
                        if (DEBUG) System.out.println("Received a user list from server: \"" + userTable.replaceAll("\n", "; ") + "\".");
                        
                        while (userTable.length() > 0) {
                            int indx = userTable.indexOf("\n");
                            String row;
                            
                            if (indx > 0) {
                                row = userTable.substring(0, indx);
                                userTable = userTable.substring(indx + 1);
                            } else {
                                row = userTable;
                                userTable = "";
                            }
                            
                            indx = row.lastIndexOf(",");
                            
                            if (indx > 0) {
                                buddyListData.addRow(new Object[]{
                                    row.substring(0, indx).trim(),
                                    row.substring(indx + 1).trim()});
                            }
                        }
                        break;
                        
                   	case StealthNetPacket.CMD_SECRETLIST:                   		
                        String secretTable = new String(pckt.data);
                        secretListData.setRowCount(0);
                        
                        if (DEBUG) System.out.println("Received a user list from server: \"" + secretTable.replaceAll("\n", "; ") + "\".");
                        
                        while (secretTable.length() > 0) {
                            int indx = secretTable.indexOf("\n");
                            String row;
                            
                            if (indx > 0) {
                                row = secretTable.substring(0, indx);
                                secretTable = secretTable.substring(indx + 1);
                            } else {
                                row = secretTable;
                                secretTable = "";
                            }
                            
                            final String values[] = row.split(";");
                            secretListData.addRow(values);
                            
                            final SecretData data = new SecretData();
                            data.description = values[2];
                            data.filename = values[3];
							secretDescriptions.put(values[0], data);
                        }
                        break;

					case StealthNetPacket.CMD_GETSECRET:						
						fName = new String(pckt.data);
						iAddr = fName.substring(fName.lastIndexOf("@") + 1);
						iPort = new Integer(iAddr.substring(iAddr.lastIndexOf(":") + 1));
						iAddr = iAddr.substring(0, iAddr.lastIndexOf(":"));
						fName = fName.substring(0, fName.lastIndexOf("@"));
						
						if (DEBUG) System.out.println("Received a get secret command from server. Target host: " + iAddr + ":" + iPort + ". The filename is \"" + fName + "\".");

						snComms = new StealthNetComms();
						snComms.initiateSession(new Socket(iAddr, iPort.intValue()));
						if (DEBUG) System.out.println("Opened a communications session with " + iAddr + ".");
						
						msgTextBox.append("[INFO] Sending out a secret.\n");

						if (DEBUG) System.out.println("Starting file transfer.");
						new StealthNetFileTransfer(snComms,	fName, true).start();
						break;

                    default:
                        System.err.println("Unrecognised command received from server.");
               }
            }
        } catch (Exception e) {
            System.err.println("Error running client thread.");
            if (DEBUG) e.printStackTrace();
        }
        
        /** Start processing packets again. */
        stealthTimer.start();
    }

    /** 
     * Main client function to execute.
     * 
     *  @param args The command line arguments.
     */
    public static void main(String[] args) {
    	/** Hostname of the server. */
    	String hostname = StealthNetComms.DEFAULT_SERVERNAME;
    	
    	/** Port that the server is listening on. */
    	int port = StealthNetComms.DEFAULT_SERVERPORT;
    	
    	/** Check if a host and port was specified at the command line. */
    	if (args.length > 0) {
    		try {
    			String[] input = args[0].split(":", 2);
    			
    			hostname = input[0];
    			if (input.length > 1)
    				port = Integer.parseInt(input[1]);
    			
    			if (port <= 0 || port > 65535)
    				throw new NumberFormatException("Invalid port number: " + port);
    		} catch (NumberFormatException e) {
    			System.err.println(e.getMessage());
    			if (DEBUG) e.printStackTrace();
                System.exit(1);
    		}
    	}
    	
        try {
            UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
        } catch (Exception e) {}

        /** Create the top-level container and contents. */
        clientFrame = new JFrame("stealthnet");
        StealthNetClient app = null;
        try {
        	app = new StealthNetClient(hostname, port);
        } catch(Exception e) {
        	System.out.println("Unable to create StealthNet client.");
        	if (DEBUG) e.printStackTrace();
        	System.exit(1);
        }
        Component contents = app.createGUI();
        clientFrame.getContentPane().add(contents, BorderLayout.CENTER);

        /** 
         * Finish setting up the GUI - add a window listener such that closing 
         * the GUI closes the application properly.
         */
        clientFrame.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) { System.exit(0); };
        });
        clientFrame.pack();
        clientFrame.setVisible(true);
    }
}

/******************************************************************************
 * END OF FILE:     StealthNetClient.java
 *****************************************************************************/