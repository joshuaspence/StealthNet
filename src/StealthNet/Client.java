/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie, Stephen Gould and Ryan Junee
 *
 * PACKAGE:         StealthNet
 * FILENAME:        Client.java
 * AUTHORS:         Matt Barrie, Stephen Gould, Ryan Junee and Joshua Spence
 * DESCRIPTION:     Implementation of StealthNet Client for ELEC5616
 *                  programming assignment. Debug code has been added to this 
 *                  class.
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
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
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

import org.apache.commons.codec.binary.Base64;

import StealthNet.Security.AsymmetricEncryption;
import StealthNet.Security.InvalidPasswordException;
import StealthNet.Security.RSAAsymmetricEncryption;

/* StealthNet.Client Class Definition ****************************************/

/** 
 * A client for the StealthNet chat program. Receives information about clients 
 * and secrets from a StealthNet server.
 * 
 * If the client wants to start a chat session with a user, then the source 
 * client sends a command to the server, containing an IP address and port 
 * number on which the source client is waiting to accept a connection from the 
 * destination client. The server relays this information to the destination 
 * client, which should then connect with the source client to start the chat 
 * session.
 * 
 * Similarly, if the clients wants to send a file to another client, then the
 * source client sends a command to the server, containing an IP address and 
 * port number on which the source client is waiting to accept a connection from
 * the destination client. The server relays this information to the destination
 * client, which should then connect with the source client to start the file 
 * transfer.
 * 
 * @author Matt Barrie
 * @author Stephen Gould
 * @author Ryan Junee
 * @author Joshua Spence
 */
public class Client {
	/** Debug options. */
	private static final boolean DEBUG_GENERAL               = Debug.isDebug("StealthNet.Client.General");
	private static final boolean DEBUG_ERROR_TRACE           = Debug.isDebug("StealthNet.Client.ErrorTrace") || Debug.isDebug("ErrorTrace");
	private static final boolean DEBUG_COMMANDS_MSG          = Debug.isDebug("StealthNet.Client.Commands.Msg");
	private static final boolean DEBUG_COMMANDS_CHAT         = Debug.isDebug("StealthNet.Client.Commands.Chat");
	private static final boolean DEBUG_COMMANDS_FTP          = Debug.isDebug("StealthNet.Client.Commands.FTP");
	private static final boolean DEBUG_COMMANDS_LIST         = Debug.isDebug("StealthNet.Client.Commands.List");
	private static final boolean DEBUG_COMMANDS_SECRETLIST   = Debug.isDebug("StealthNet.Client.Commands.SecretList");
	private static final boolean DEBUG_COMMANDS_GETSECRET    = Debug.isDebug("StealthNet.Client.Commands.GetSecret");
	private static final boolean DEBUG_ASYMMETRIC_ENCRYPTION = Debug.isDebug("StealthNet.Client.AsymmetricEncryption");
	
	/** StealthNet server options. */
	private final String serverHostname;
	private final int serverPort;
	private static final String SERVER_PUBLIC_KEY_FILE = "keys/server/public.key";
	
	/** The main frame for this client. */
    private static JFrame clientFrame;
    
    /** A text box used to display messages to the user. */
    private JTextArea msgTextBox;
    
    /** Button to log into StealthNet. */
    private JButton loginBtn;
    
    /** Used for communications with the StealthNet server. */
    private Comms stealthComms = null;
    
    /** Public-private keys to identify this client. */
    private AsymmetricEncryption asymmetricEncryptionProvider;
    
    /** A timer to periodically process incoming packets. */
    private final Timer stealthTimer;
    
    /** The ID of this (client) user. */
    private String userID = null;
    
    /** Buddy list. */
    private JTable buddyTable = null;
    private DefaultTableModel buddyListData = null;
    
    /** User list. */
    private class UserData {
		boolean online = false;
		PublicKey publicKey = null;
	}
	private static final Hashtable<String, UserData> userList = new Hashtable<String, UserData>();
    
    /** Secret list. */
    private DefaultTableModel secretListData = null;
    
    /** Graphical representation of the secret list. */
    private JTable secretTable = null;
    
    /** Field to show the remaining number of credits. */
	JTextField creditsBox;
	
	/** Credits. */
    private int credits = 100;

    /** Secret data. */
	private class SecretData {
		String description = null;
		String filename = null;
	}

	/** A list of secret data, indexed by secret name. */
	static private Hashtable<String, SecretData> secretDescriptions = new Hashtable<String, SecretData>();
    
    /** Constructor. */
    public Client() {    	
    	/** Create a timer to process packets every 100ms. */
    	this.stealthTimer = new Timer(100, new ActionListener() {
            public void actionPerformed(ActionEvent e) { processPackets(); }
        });
        
        this.serverHostname = Comms.DEFAULT_SERVERNAME;
        this.serverPort = Comms.DEFAULT_SERVERPORT;
    }

    /** 
	 * Constructor. 
	 * 
	 * @param s The hostname of the StealthNet server.
	 * @param p The port that the StealthNet server is listening on.
	 */
    public Client(String s, int p) {    	
    	/** Create a timer to process packets every 100ms. */
        this.stealthTimer = new Timer(100, new ActionListener() {
            public void actionPerformed(ActionEvent e) { processPackets(); }
        });
        
        this.serverHostname = s;
        this.serverPort = p;
    }
    
    /**
     * Create the GUI for the client instance.
     * 
     * @return An AWT component containing the client GUI.
     */
	public Component createGUI() {
        final JPanel pane = new JPanel();
            	
        /** Create user list. */
        buddyListData = new DefaultTableModel() {
			private static final long serialVersionUID = 1L;

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
			private static final long serialVersionUID = 1L;

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

    /** 
     * Login to StealthNet. This will establish comms to the StealthNet server. 
     * The communications will be encrypted using the server's public key. This 
     * means that if another party is masquerading as the server, then (without 
     * the server's private key) they are unable to decrypt the packets.
     */
    private synchronized void login() {
    	if (DEBUG_GENERAL) System.out.println("Logging in to StealthNet.");
    	
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
            
            do {
	            /** Get the password for the private key. */
	            String password = null;
	            password = JOptionPane.showInputDialog("Password:", password);
	            if (password == null) 
	            	return;
	            
	            /** 
	             * Set up asymmetric encryption. Get server public key from JAR file.
	             */
	            PublicKey serverPublicKey = Utility.getPublicKey(SERVER_PUBLIC_KEY_FILE);
	            if (serverPublicKey == null) {
	            	System.err.println("Unable to determine server public key.");
	    			System.exit(1);
	            }
	            
	            final String publicKeyPath  = "keys/clients/" + userID + "/public.key";
	            final String privateKeyPath = "keys/clients/" + userID + "/private.key";
	            try {
	            	asymmetricEncryptionProvider = Utility.getPublicPrivateKeys(publicKeyPath, privateKeyPath, password);
	            } catch (InvalidPasswordException e) {
	            	JOptionPane.showMessageDialog(null, "The password you entered was incorrect.", "Invalid password", JOptionPane.ERROR_MESSAGE);
	            	continue;
	            } catch (Exception e) {
	            	System.err.println(e.getMessage());
	            	if (DEBUG_ERROR_TRACE) e.printStackTrace();
	            	System.exit(1);
	            }
            } while (asymmetricEncryptionProvider == null);
           	
    		if (DEBUG_ASYMMETRIC_ENCRYPTION) {
				final String publicKeyString = new String(Utility.getHexValue(asymmetricEncryptionProvider.getPublicKey().getEncoded()));
		    	final String privateKeyString = new String(Utility.getHexValue(asymmetricEncryptionProvider.getPrivateKey().getEncoded()));
		    	System.out.println("Public key: " + publicKeyString);
		    	System.out.println("Private key: " + privateKeyString);
    		}
            
            /** Initiate a connection with the StealthNet server. */
            /** TODO: Probably want a timeout on this. */
            if (DEBUG_GENERAL) System.out.println("Initiating a connection with StealthNet server '" + serverHostname + "' on port " + serverPort + ".");
            stealthComms = new Comms(asymmetricEncryptionProvider);
            stealthComms.initiateSession(new Socket(serverHostname, serverPort));
            
            /** Send the server a login command. */
            if (DEBUG_GENERAL) System.out.println("Sending the server a login packet for user \"" + userID + "\".");
            stealthComms.sendPacket(DecryptedPacket.CMD_LOGIN, userID);
            
            /** Start periodically checking for packets. */
            stealthTimer.start();
        } catch (UnknownHostException e) {
        	System.err.println("Unknown host for StealthNet server: \"" + serverHostname + "\".");
            msgTextBox.append("[*ERR*] Unknown host: '" + serverHostname + "'.\n");
            if (DEBUG_ERROR_TRACE) e.printStackTrace();
            return;
        } catch (IOException e) {
        	System.err.println("Could not connect to StealthNet server on port " + serverPort + ".");
            msgTextBox.append("[*ERR*] Could not connect to host on port " + serverPort + ".\n");
            if (DEBUG_ERROR_TRACE) e.printStackTrace();
            return;
        }
        
        /** NOTE: We should now be connected to the StealthNet server. */

		msgTextBox.append("Connected to StealthNet.\n");
		if (DEBUG_GENERAL) System.out.println("Connected to StealthNet.");
		
		/** Set the frame title. */
		clientFrame.setTitle("stealthnet [" + userID + "]");
		
		/** Change the login button to a logout button. */
        loginBtn.setIcon(new ImageIcon(this.getClass().getClassLoader().getResource("img/logout.gif")));
        loginBtn.setToolTipText("Logout");
    }

    /** Logout of StealthNet. */
    private synchronized void logout() {
    	if (DEBUG_GENERAL) System.out.println("Logging out of StealthNet.");
    	
        if (stealthComms != null) {
        	/** Stop periodically checking for packets. */
            stealthTimer.stop();
            
            /** Send the server a logout command. */
            stealthComms.sendPacket(DecryptedPacket.CMD_LOGOUT);
            
            /** Terminate session. */
            stealthComms.terminateSession();
            stealthComms = null;
            
            /** Change the logout button back to a login button. */
            loginBtn.setIcon(new ImageIcon(this.getClass().getClassLoader().getResource("img/login.gif")));
            loginBtn.setToolTipText("Login");
            
            /** Hide user and secret list. */
            buddyListData.setRowCount(0);
            secretListData.setRowCount(0);
            userList.clear();
            
            msgTextBox.append("Disconnected.\n");
            if (DEBUG_GENERAL) System.out.println("Disconnected.");
        }
    }

    /** Create a secret. */
	private void createSecret() {
		if (DEBUG_GENERAL) System.out.println("Creating secret.");
		
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
	        	if (DEBUG_GENERAL) System.out.println("Sending secret details to server. Secret name is \"" + name + "\". Secret cost is " + cost + ". Secret description is \"" + description + "\". Secret file is \"" + fileOpen.getDirectory() + fileOpen.getFile() + "\".");
	        	stealthComms.sendPacket(DecryptedPacket.CMD_CREATESECRET, userMsg);
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
		
		if (DEBUG_GENERAL) System.out.println("Attempting to purchase secret \"" + name + "\".");
		
		if (data == null)
			return;

		/** Set up socket on a free port for file transfer of the secret file. */
		ServerSocket ftpSocket = null;
		try {
			ftpSocket = new ServerSocket(0);
		} catch (IOException e) {
			System.err.println("Could not set up listening port for file transfer.");
			msgTextBox.append("[*ERR*] Transfer failed.\n");
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
			return;
		}
		
		if (DEBUG_GENERAL) System.out.println("Set up socket on port " + ftpSocket.getLocalPort() + " for transfer of secret file \"" + name + "\".");

		/** Discover our own IP address. */
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
		if (DEBUG_GENERAL) System.out.println("Sending get secret message to server. Target client should connect on '" + iAddr + ":" + ftpSocket.getLocalPort() + "'.");
		stealthComms.sendPacket(DecryptedPacket.CMD_GETSECRET, name + "@" + iAddr);

		/** Choose where to save the secret file. */
		final FileDialog fileSave = new FileDialog(clientFrame, "Save As...", FileDialog.SAVE);
		fileSave.setFile(data.filename);
		fileSave.setVisible(true);
		
		if (DEBUG_GENERAL) System.out.println("Will save secret file \"" + name + "\" to \"" + fileSave.getDirectory() + fileSave.getFile() + "\".");
		
		if ((fileSave.getFile() != null) && (fileSave.getFile().length() > 0)) {
			/** Wait for user to connect, then start file transfer. */
			try {
				if (DEBUG_GENERAL) System.out.println("Waiting for target client to connect.");
				
				/** Set a 2 second timeout on the socket. */
				ftpSocket.setSoTimeout(2000);
				final Comms snComms = new Comms();
				final Socket conn = ftpSocket.accept();
				snComms.acceptSession(conn);
				
				if (DEBUG_GENERAL) System.out.println("Accepted connection from '" + conn.getInetAddress() + ":" + conn.getPort() + "' for transfer of secret.");
				final FileTransfer ft = new FileTransfer(snComms, fileSave.getDirectory() + fileSave.getFile(), false);
				ft.start();
			} catch (Exception e) {
				System.err.println("Transfer failed.");
				msgTextBox.append("[*ERR*] Transfer failed.\n");
				if (DEBUG_ERROR_TRACE) e.printStackTrace();
			}	
		}
    }    

    /**
     * Check if we are able to send a message to a specified user.
     * 
     * @param row The user to check.
     */
	private boolean isOKtoSendtoRow(int row) {
		final String myid = (String) buddyTable.getValueAt(row, 0);
		final String mystatus = (String) buddyTable.getValueAt(row,1);

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
        final String myid = buddyTable.getValueAt(row, 0).toString().trim();
        final PublicKey peer = userList.get(myid).publicKey;
        		
        /** Set up socket on a free port for the chat session. */
        ServerSocket chatSocket = null;
        try {
            chatSocket = new ServerSocket(0);
        } catch (IOException e) {
        	System.err.println("Chat failed. Failed to create ServerSocket.");
            msgTextBox.append("[*ERR*] Chat failed.\n");
            if (DEBUG_ERROR_TRACE) e.printStackTrace();
            return;
        }
        
        if (DEBUG_GENERAL) System.out.println("Set up socket on port " + chatSocket.getLocalPort() + " for chat session with \"" + myid + "\".");

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
        
        if (DEBUG_GENERAL) System.out.println("Sending chat message to server. Target client should connect on '" + iAddr + ":" + chatSocket.getLocalPort() + "'.");
        stealthComms.sendPacket(DecryptedPacket.CMD_CHAT, myid + "@" + iAddr);
        
        /** Wait for user to connect and open chat window. */
        try {
        	if (DEBUG_GENERAL) System.out.println("Waiting for target client to connect.");
        	
        	/** Set 2 second timeout on socket. */
            chatSocket.setSoTimeout(2000);
            
            /**
             * Create communications to the peer. Note that the peer will have 
             * our public key, and hence can encrypt the communications using 
             * asymmetric encryption immediately.
             */
            final Comms snComms = new Comms(new RSAAsymmetricEncryption(asymmetricEncryptionProvider, peer), true);
            final Socket conn = chatSocket.accept();
            snComms.acceptSession(conn);
            
            if (DEBUG_GENERAL) System.out.println("Accepted connection from '" + conn.getInetAddress() + ":" + conn.getPort() + "' for chat session.");
            final Chat chat = new Chat(userID, snComms);
            chat.start();
        } catch (Exception e) {
        	System.err.println("Chat failed.");
            msgTextBox.append("[*ERR*] Chat failed.\n");
            if (DEBUG_ERROR_TRACE) e.printStackTrace();
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
		final String myid = (String) buddyTable.getValueAt(row, 0);
		final PublicKey peer = userList.get(myid).publicKey;

		/** Select the file to send. */
        final FileDialog fileOpen = new FileDialog(clientFrame, "Open...", FileDialog.LOAD);
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
            if (DEBUG_ERROR_TRACE) e.printStackTrace();
            return;
        }

        if (DEBUG_GENERAL) System.out.println("Set up socket on port " + ftpSocket.getLocalPort() + " for transfer of file \"" + fileOpen.getFile() + "\" to \"" + myid + "\".");
        
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
        
        if (DEBUG_GENERAL) System.out.println("Sending FTP message to server. Target client should connect on '" + iAddr + ":" + ftpSocket.getLocalPort() + "'.");
        stealthComms.sendPacket(DecryptedPacket.CMD_FTP,  myid + "@" + iAddr + "#" + fileOpen.getFile());

        /** Wait for user to connect, then start file transfer. */
        try {
        	if (DEBUG_GENERAL) System.out.println("Waiting for target client to connect for file transfer.");
        	
        	/** Set 2 second timeout on socket. */
            ftpSocket.setSoTimeout(2000);
            
            /**
             * Create communications to the peer. Note that the peer will have 
             * our public key, and hence can encrypt the communications using 
             * asymmetric encryption immediately.
             */
            final Comms snComms = new Comms(new RSAAsymmetricEncryption(asymmetricEncryptionProvider, peer), true);
            final Socket conn = ftpSocket.accept();
            snComms.acceptSession(conn);
            
            if (DEBUG_GENERAL) System.out.println("Accepted connection from '" + conn.getInetAddress() + ":" + conn.getPort() + "' for FTP transfer.");
            final FileTransfer ft = new FileTransfer(snComms, fileOpen.getDirectory() + fileOpen.getFile(), true);
            ft.start();
        } catch (Exception e) {
        	System.err.println("FTP failed.");
            msgTextBox.append("[*ERR*] FTP failed.\n");
            if (DEBUG_ERROR_TRACE) e.printStackTrace();
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
			if (DEBUG_ERROR_TRACE) e.printStackTrace();
            return;
        }

        String iAddr, fName, sourceUser = null;
        Integer iPort = null;
        Comms snComms = null;
        PublicKey peer = null;
        DecryptedPacket pckt = new DecryptedPacket();

        /** No need to process packets while we are already processing packets. */
        stealthTimer.stop();

        try {
            /** Check for message from server. */
            while (stealthComms.recvReady()) {
                pckt = stealthComms.recvPacket();
                
                if (pckt == null)
                	break;
                
                if (DEBUG_GENERAL) System.out.println("Received packet. Packet command: " + DecryptedPacket.getCommandName(pckt.command) + ". Packet data: \"" + new String(pckt.data).replaceAll("\n", ";") + "\".");
                
                switch (pckt.command) {
	                /***********************************************************
					 * Message command
					 **********************************************************/
                    case DecryptedPacket.CMD_MSG:
                    	final String msg = new String(pckt.data);
                    	if (DEBUG_COMMANDS_MSG) System.out.println("Received a message command. Message: \"" + msg + "\".");
                	    msgTextBox.append(msg + "\n");
                        break;

                    /***********************************************************
					 * Chat command
					 **********************************************************/
                    case DecryptedPacket.CMD_CHAT:
                    	/** 
                    	 * NOTE: Data will be of the form 
                    	 * "user@host:port".
                    	 */
                        final String chatData = new String(pckt.data);
                        
                        iAddr =             chatData.split("@")[1].split(":")[0];
                        iPort = new Integer(chatData.split("@")[1].split(":")[1]);
                        
                        /** Get the peer public key. */
                        sourceUser =        chatData.split("@")[0];
                        peer = userList.get(sourceUser).publicKey;
                        
                        if (DEBUG_COMMANDS_CHAT) System.out.println("Received a chat command. Target host: '" + iAddr + ":" + iPort + "'.");
                        
                        /**
                         * Create communications to the peer. Note that the peer
                         * will have our public key, and hence can encrypt the 
                         * communications using asymmetric encryption 
                         * immediately.
                         */
                        snComms = new Comms(new RSAAsymmetricEncryption(asymmetricEncryptionProvider, peer), true);
                        snComms.initiateSession(new Socket(iAddr, iPort.intValue()));
                        if (DEBUG_GENERAL) System.out.println("Opened a communications session with '" + iAddr + "'.");
                        
                        
                        final Chat chat = new Chat(userID, snComms);
                        chat.start();
                        if (DEBUG_GENERAL) System.out.println("Started a chat session with '" + iAddr + "'.");
                        break;

                    /***********************************************************
					 * FTP command
					 **********************************************************/
                    case DecryptedPacket.CMD_FTP:  
                    	/** 
                    	 * NOTE: Data will be of the form 
                    	 * "user@host:port#filename".
                    	 */
                        final String ftpData = new String(pckt.data);
                        fName =             ftpData.split("@")[1].split("#")[1];
                        iAddr =             ftpData.split("@")[1].split("#")[0].split(":")[0];
                        iPort = new Integer(ftpData.split("@")[1].split("#")[0].split(":")[1]);
                        
                        /** Get the peer public key. */
                        sourceUser =        ftpData.split("@")[0];
                        peer = userList.get(sourceUser).publicKey;
                        
                        if (DEBUG_COMMANDS_FTP) System.out.println("Received a file transfer command. Target host: '" + iAddr + ":" + iPort + "'.");

                        /**
                         * Create communications to the peer. Note that the peer
                         * will have our public key, and hence can encrypt the 
                         * communications using asymmetric encryption 
                         * immediately.
                         */
                        snComms = new Comms(new RSAAsymmetricEncryption(asymmetricEncryptionProvider, peer), true);
                        snComms.initiateSession(new Socket(iAddr, iPort.intValue()));
                        if (DEBUG_GENERAL) System.out.println("Opened a communications session with '" + iAddr + "'.");
                        
                        final FileDialog fileSave = new FileDialog(clientFrame, "Save As...", FileDialog.SAVE);
                        fileSave.setFile(fName);
                        fileSave.setVisible(true);
                        if ((fileSave.getFile() != null) && (fileSave.getFile().length() > 0)) {
                        	if (DEBUG_GENERAL) System.out.println("File will be saved to \"" + fileSave.getDirectory() + fileSave.getFile() + "\". Starting file transfer.");                        	
                            final FileTransfer ft = new FileTransfer(snComms, fileSave.getDirectory() + fileSave.getFile(), false);
                            ft.start();
                        }
                        break;

                    /***********************************************************
					 * List command
					 **********************************************************/
                    case DecryptedPacket.CMD_LIST:                    	
                        String userTable = new String(pckt.data);
                        buddyListData.setRowCount(0);
                        
                        if (DEBUG_COMMANDS_LIST) System.out.println("Received a user list: \"" + userTable.replaceAll("\n", "; ") + "\".");
                        
                        userList.clear();
                        while (userTable.length() > 0) {
                            final int indx = userTable.indexOf("\n");
                            String row;
                            
                            if (indx > 0) {
                                row = userTable.substring(0, indx);
                                userTable = userTable.substring(indx + 1);
                            } else {
                                row = userTable;
                                userTable = "";
                            }
                            
                            /** Add the user to the user list. */
                            final String userID = row.split(";")[0].trim();
                            final UserData userData = new UserData();
                            userData.online = (row.split(";")[1].trim().compareTo("true") == 0);
                            try {
                            	final KeyFactory factory = KeyFactory.getInstance(RSAAsymmetricEncryption.ALGORITHM);
                            	final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(row.split(";")[2].trim()));
                            	userData.publicKey = factory.generatePublic(keySpec);
                            } catch (Exception e) {
                            	System.err.println("Failed to parse public key.");			
                            	if (DEBUG_ERROR_TRACE) e.printStackTrace();
                            	continue;
                            }
                            userList.put(userID, userData);
                            
                            /** Add the user to the GUI list. */
                            buddyListData.addRow(new Object[] {
                            	userID,
                            	(userData.online ? "true" : "false")
                            	});
                        }
                        break;
                        
                    /***********************************************************
					 * Secret List command
					 **********************************************************/
                   	case DecryptedPacket.CMD_SECRETLIST:                   		
                        String secretTable = new String(pckt.data);
                        secretListData.setRowCount(0);
                        
                        if (DEBUG_COMMANDS_SECRETLIST) System.out.println("Received a secret list: \"" + secretTable.replaceAll("\n", "; ") + "\".");
                        
                        while (secretTable.length() > 0) {
                            final int indx = secretTable.indexOf("\n");
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

                    /***********************************************************
					 * Get Secret command
					 **********************************************************/
					case DecryptedPacket.CMD_GETSECRET:
						/** TODO: fix*/
						fName = new String(pckt.data);
						iAddr = fName.substring(fName.lastIndexOf("@") + 1);
						iPort = new Integer(iAddr.substring(iAddr.lastIndexOf(":") + 1));
						iAddr = iAddr.substring(0, iAddr.lastIndexOf(":"));
						fName = fName.substring(0, fName.lastIndexOf("@"));
						
						if (DEBUG_COMMANDS_GETSECRET) System.out.println("Received a get secret command. Target host: '" + iAddr + ":" + iPort + "'. The filename is \"" + fName + "\".");

						snComms = new Comms();
						snComms.initiateSession(new Socket(iAddr, iPort.intValue()));
						if (DEBUG_GENERAL) System.out.println("Opened a communications session with '" + iAddr + "'.");
						
						msgTextBox.append("[INFO] Sending out a secret.\n");
						if (DEBUG_GENERAL) System.out.println("Starting file transfer.");
						final FileTransfer ft = new FileTransfer(snComms, fName, true);
						ft.start();
						break;

					/***********************************************************
					 * Unknown command
					 **********************************************************/
                    default:
                        System.err.println("Unrecognised command received from server.");
               }
            }
        } catch (Exception e) {
            System.err.println("Error running client thread.");
            if (DEBUG_ERROR_TRACE) e.printStackTrace();
        }
        
        /** Start processing packets again. */
        stealthTimer.start();
    }

    /** 
     * Main client function to execute.
     * 
     * @param args The command line arguments.
     */
    public static void main(String[] args) {
    	/** Hostname of the proxy. */
    	String hostname = ProxyComms.DEFAULT_PROXYNAME;
    	
    	/** Port that the proxy is listening on. */
    	int port = ProxyComms.DEFAULT_PROXYPORT;
    	
    	/** Check if a host and port was specified at the command line. */
    	if (args.length > 0) {
    		try {
    			final String[] input = args[0].split(":", 2);
    			
    			hostname = input[0];
    			if (input.length > 1)
    				port = Integer.parseInt(input[1]);
    			
    			if (port <= 0 || port > 65535)
    				throw new NumberFormatException("Invalid port number: " + port);
    		} catch (NumberFormatException e) {
    			System.err.println(e.getMessage());
    			if (DEBUG_ERROR_TRACE) e.printStackTrace();
                System.exit(1);
    		}
    	}
    	
        try {
            UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
        } catch (Exception e) {}

        /** Create the top-level container and contents. */
        clientFrame = new JFrame("stealthnet");
        Client app = null;
        try {
        	app = new Client(hostname, port);
        } catch (Exception e) {
        	System.out.println("Unable to create StealthNet client.");
        	if (DEBUG_ERROR_TRACE) e.printStackTrace();
        	System.exit(1);
        }
        final Component contents = app.createGUI();
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
 * END OF FILE:     Client.java
 *****************************************************************************/