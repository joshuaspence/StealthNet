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

import java.util.Hashtable;

import java.io.IOException;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.net.URL;

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
import javax.swing.table.DefaultTableModel;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.JOptionPane;

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

/* StealthNetClient Class Definition *****************************************/

public class StealthNetClient {
    private static JFrame clientFrame;
    private JTextArea msgTextBox;
    private JButton loginBtn;
    private StealthNetComms stealthComms = null;
    private javax.swing.Timer stealthTimer;
    private String userID = null;
    private JTable buddyTable = null, secretTable = null;
    private DefaultTableModel buddyListData = null, secretListData = null;
	JTextField creditsBox;
	private final ClassLoader cldr = this.getClass().getClassLoader();
	
    private int credits = 100;		// CHANGEME: Give them 100 credits for demonstration purposes

	private class SecretData {
		String description = null;
		String filename = null;
	}

	static private Hashtable<String, SecretData> secretDescriptions = new Hashtable<String, SecretData>();

    public StealthNetClient() {
        stealthTimer = new Timer(100, new ActionListener() {
            public void actionPerformed(ActionEvent e) { processPackets(); }
        });
    }

    @SuppressWarnings("serial")
	public Component createGUI() {
        JPanel pane = new JPanel();
            	
        // create buddy list
        buddyListData = new DefaultTableModel() {
        	public boolean isCellEditable(int row, int col) { return false; };
        };
        buddyListData.addColumn("User ID");
        buddyListData.addColumn("Online");
        buddyTable = new JTable(buddyListData);
        buddyTable.setPreferredScrollableViewportSize(new Dimension(200, 100));
        buddyTable.getColumnModel().getColumn(0).setPreferredWidth(180);
        
        JScrollPane buddyScrollPane = new JScrollPane(buddyTable);
        buddyScrollPane.setBorder(
            BorderFactory.createCompoundBorder(
                BorderFactory.createCompoundBorder(
                    BorderFactory.createTitledBorder("User List"),
                    BorderFactory.createEmptyBorder(0,0,0,0)),
                buddyScrollPane.getBorder()));
               
        // add mouse listen for popup windows
		// act on JTable row right-click
		MouseListener ml = new MouseAdapter() {
			JPopupMenu popup;
			int row;
			
			public void mouseReleased(MouseEvent e) {	
				if (e.isShiftDown()||e.isControlDown()||e.isAltDown()) {
       				return;
      			}
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

        // create secret window
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
			
			public void mouseReleased(MouseEvent e) {
				if (e.isShiftDown() || e.isControlDown() || e.isAltDown()) {
       				return;
      			} else if (e.isPopupTrigger()) {
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
        
        JScrollPane secretScrollPane = new JScrollPane(secretTable);
        secretScrollPane.setBorder(
            BorderFactory.createCompoundBorder(
                BorderFactory.createCompoundBorder(
                    BorderFactory.createTitledBorder("Secrets List"),
                    BorderFactory.createEmptyBorder(0,0,0,0)),
                secretScrollPane.getBorder()));


        // create instant message window
        msgTextBox = new JTextArea("Authentication required.\n");
        msgTextBox.setLineWrap(true);
        msgTextBox.setWrapStyleWord(true);
        msgTextBox.setEditable(false);
        JScrollPane msgScrollPane = new JScrollPane(msgTextBox);
        msgScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        msgScrollPane.setPreferredSize(new Dimension(200, 100));
        msgScrollPane.setBorder(
            BorderFactory.createCompoundBorder(
                BorderFactory.createCompoundBorder(
                    BorderFactory.createTitledBorder("Console"),
                    BorderFactory.createEmptyBorder(0,0,0,0)),
                msgScrollPane.getBorder()));

        // create split pane for buddy list and messages
        final JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, buddyScrollPane, secretScrollPane);
        splitPane.setOneTouchExpandable(true);
        splitPane.setDividerLocation(150);

		final JSplitPane topPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, splitPane, msgScrollPane);
        topPane.setOneTouchExpandable(true);  

		// Credits display
		JPanel creditsPane = new JPanel();
		creditsPane.setLayout(new GridLayout(1, 0));
		creditsPane.setPreferredSize(new Dimension(180, 30));
		creditsPane.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
		creditsPane.add(new JLabel("Credits:  ", SwingConstants.RIGHT));
		creditsBox = new JTextField(new Integer(credits).toString());
		creditsBox.setEditable(false);
		creditsPane.add(creditsBox);
                
        // create buttons (login, send message, chat, ftp)
        URL loginImageURL = cldr.getResource("img/login.gif");
        loginBtn = new JButton(new ImageIcon(loginImageURL));
        loginBtn.setVerticalTextPosition(AbstractButton.BOTTOM);
        loginBtn.setHorizontalTextPosition(AbstractButton.CENTER);
        loginBtn.setMnemonic(KeyEvent.VK_N);
        loginBtn.setToolTipText("Login");
        loginBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (stealthComms == null) { login(); } else { logout(); }
            }
        });

        URL msgImageURL = cldr.getResource("img/msg.gif");
        final JButton msgBtn = new JButton(new ImageIcon(msgImageURL));
        msgBtn.setVerticalTextPosition(AbstractButton.BOTTOM);
        msgBtn.setHorizontalTextPosition(AbstractButton.CENTER);
        msgBtn.setMnemonic(KeyEvent.VK_M);
        msgBtn.setToolTipText("Create Secret");
        msgBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) { createSecret(); }
        });

        JPanel btnPane = new JPanel();
        btnPane.setLayout(new GridLayout(1, 0));
        btnPane.setPreferredSize(new Dimension(180, 40));
        btnPane.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
        btnPane.add(loginBtn);
        btnPane.add(msgBtn);

		JPanel bottomPane = new JPanel();
		bottomPane.setLayout(new BorderLayout());
		bottomPane.add(creditsPane, BorderLayout.NORTH);
		bottomPane.add(btnPane, BorderLayout.SOUTH);

        // create top-level panel and add components
        pane.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));
        pane.setLayout(new BorderLayout());
        pane.add(topPane, BorderLayout.NORTH);
        pane.add(bottomPane, BorderLayout.SOUTH);

        return pane;
    }

    private synchronized void login() {
        if (stealthComms != null) {
            msgTextBox.append("[*ERR*] Already logged in.\n");
            return;
        }

        try {
            userID = JOptionPane.showInputDialog("Login:", userID);
            if (userID == null) return;
            
            stealthComms = new StealthNetComms();
            stealthComms.initiateSession(new Socket(StealthNetComms.SERVERNAME, StealthNetComms.SERVERPORT));
            stealthComms.sendPacket(StealthNetPacket.CMD_LOGIN, userID);
            stealthTimer.start();
        } catch (UnknownHostException e) {
            msgTextBox.append("[*ERR*] Unknown host: " + StealthNetComms.SERVERNAME + "\n");
        } catch (IOException e) {
            msgTextBox.append("[*ERR*] Could not connect to host: " + StealthNetComms.SERVERNAME + "\n");
        }

		msgTextBox.append("Connected to stealthnet.\n");
		clientFrame.setTitle("stealthnet [" + userID + "]");
		URL logoutImageURL = cldr.getResource("img/logout.gif");
        loginBtn.setIcon(new ImageIcon(logoutImageURL));
        loginBtn.setToolTipText("Logout");
    }

    private synchronized void logout() {
        if (stealthComms != null) {
            stealthTimer.stop();
            stealthComms.sendPacket(StealthNetPacket.CMD_LOGOUT);
            stealthComms.terminateSession();
            stealthComms = null;
            
            URL loginImageURL = cldr.getResource("img/login.gif");
            loginBtn.setIcon(new ImageIcon(loginImageURL));
            loginBtn.setToolTipText("Login");
            
            buddyListData.setRowCount(0);
            secretListData.setRowCount(0);
            msgTextBox.append("Disconnected.\n");
        }
    }

    @SuppressWarnings("unused")
	private void createSecret() {
    	String userMsg;
    	String name = "", description = "", cost = "";
    	
        if (stealthComms == null) {
            msgTextBox.append("[*ERR*] Not logged in.\n");
            return;
        }

		name = JOptionPane.showInputDialog("Secret Name:", name);
		description = JOptionPane.showInputDialog("Secret Description:", description);
		cost = JOptionPane.showInputDialog("Secret Cost (credits):", cost);

        FileDialog fileOpen = new FileDialog(clientFrame, "Select Secret File....", FileDialog.LOAD);
        fileOpen.setVisible(true);
        if (fileOpen.getFile().length() == 0)
            return;
	
		userMsg = name + ";" + description + ";" + cost + ";" + fileOpen.getDirectory() + ";" + fileOpen.getFile();
        if (userMsg == null) return;
        stealthComms.sendPacket(StealthNetPacket.CMD_CREATESECRET, userMsg);
    }

	private void secretDetails(int row) {
		String name;
		SecretData data;
		
		name = (String) secretTable.getValueAt(row,0);
		data = (SecretData) secretDescriptions.get(name);
		if (data != null) {
			JOptionPane.showMessageDialog(null,data.description,"Details of Secret: " + name, JOptionPane.PLAIN_MESSAGE);			
		}
				
		return;
	}

    private void purchaseSecret(int row) {
		String name = (String) secretTable.getValueAt(row, 0);
		SecretData data = secretDescriptions.get(name);
		if (data == null)
			return;

		// set up socket on a free port
		ServerSocket ftpSocket = null;
		try {
			ftpSocket = new ServerSocket(0);
		} catch (IOException e) {
			System.err.println("could not set up listening port");
			msgTextBox.append("[*ERR*] Transfer failed.\n");
			return;
		}

		// send request to server
		String iAddr;
		try {
			iAddr = InetAddress.getLocalHost().toString();
			if (iAddr.lastIndexOf("/") > 0)
				iAddr = iAddr.substring(0, iAddr.lastIndexOf("/"));
		} catch (UnknownHostException e) {
			iAddr = "localhost";
		}
		iAddr += ":" + Integer.toString(ftpSocket.getLocalPort());
		stealthComms.sendPacket(StealthNetPacket.CMD_GETSECRET, name + "@" + iAddr);

		FileDialog fileSave = new FileDialog(clientFrame, "Save As...", FileDialog.SAVE);
		fileSave.setFile(data.filename);
		fileSave.setVisible(true);
		
		if ((fileSave.getFile() != null) && (fileSave.getFile().length() > 0)) {
			// wait for user to connect, then start file transfer
			try {
				ftpSocket.setSoTimeout(2000);  // 2 second timeout
				StealthNetComms snComms = new StealthNetComms();
				snComms.acceptSession(ftpSocket.accept());
				new StealthNetFileTransfer(snComms, fileSave.getDirectory() + fileSave.getFile(), false).start();
			} catch (Exception e) {
				msgTextBox.append("[*ERR*] Transfer failed.\n");
			}	
		}
    }    

	private boolean isOKtoSendtoRow(int row) {
		String myid, mystatus;

		myid = (String) buddyTable.getValueAt(row, 0);
		mystatus = (String) buddyTable.getValueAt(row,1);

		if (myid.equals(userID)) {
		   	msgTextBox.append("[*ERR*] Can't send to self.\n");
		   	return false;
		}

        // check if the user is logged in
        if (mystatus.equals("false")) {
        	msgTextBox.append("[*ERR*] User is not online.\n");
        	return false;
        }
        
        return true;
	}
	
	private void startChat(int row) {
		if (!isOKtoSendtoRow(row)) {
			return;
		}
        
        String myid = (String) buddyTable.getValueAt(row, 0);
        		
        // set up socket on a free port
        ServerSocket chatSocket = null;

        try {
            chatSocket = new ServerSocket(0);
        } catch (IOException e) {
            msgTextBox.append("[*ERR*] Chat failed.\n");
            return;
        }

        // send message to server with target user and listening address and port
        String iAddr;
        try {
            iAddr = InetAddress.getLocalHost().toString();
            if (iAddr.lastIndexOf("/") > 0)
                iAddr = iAddr.substring(0, iAddr.lastIndexOf("/"));
        } catch (UnknownHostException e) {
            iAddr = "localhost";
        }
        iAddr += ":" + Integer.toString(chatSocket.getLocalPort());
        stealthComms.sendPacket(StealthNetPacket.CMD_CHAT, myid + "@" + iAddr);

        // wait for user to connect and open chat window
        try {
            chatSocket.setSoTimeout(2000);  // 2 second timeout
            StealthNetComms snComms = new StealthNetComms();
            snComms.acceptSession(chatSocket.accept());
            new StealthNetChat(userID, snComms).start();
        } catch (Exception e) {
            msgTextBox.append("[*ERR*] Chat failed.\n");
        }
    }
   
    private void sendFile(int row) {
		if (!isOKtoSendtoRow(row)) {
			return;
		}
		
		String myid = (String) buddyTable.getValueAt(row, 0);

        FileDialog fileOpen = new FileDialog(clientFrame, "Open...", FileDialog.LOAD);
        fileOpen.setVisible(true);
        if (fileOpen.getFile().length() == 0)
            return;

        // set up socket on a free port
        ServerSocket ftpSocket = null;
        try {
            ftpSocket = new ServerSocket(0);
        } catch (IOException e) {
            System.err.println("could not set up listening port");
            msgTextBox.append("[*ERR*] FTP failed.\n");
            return;
        }

        // send message to server with target user and listening address and port
        String iAddr;
        try {
            iAddr = InetAddress.getLocalHost().toString();
            if (iAddr.lastIndexOf("/") > 0)
                iAddr = iAddr.substring(0, iAddr.lastIndexOf("/"));
        } catch (UnknownHostException e) {
            iAddr = "localhost";
        }
        iAddr += ":" + Integer.toString(ftpSocket.getLocalPort());
        stealthComms.sendPacket(StealthNetPacket.CMD_FTP, myid + "@" + iAddr + "#" + fileOpen.getFile());

        // wait for user to connect, then start file transfer
        try {
            ftpSocket.setSoTimeout(2000);  // 2 second timeout
            StealthNetComms snComms = new StealthNetComms();
            snComms.acceptSession(ftpSocket.accept());
            new StealthNetFileTransfer(snComms, fileOpen.getDirectory() + fileOpen.getFile(), true).start();
        } catch (Exception e) {
            msgTextBox.append("[*ERR*] FTP failed.\n");
        }
    }

    private void processPackets() {
		// Update credits box, stick it here for convenience
		creditsBox.setText(new Integer(credits).toString());
 
        try {
            if ((stealthComms == null) || (!stealthComms.recvReady()))
                return;
        } catch (IOException e) {
			msgTextBox.append("[*ERR*] The server appears to be down.\n");
            return;
        }

        StealthNetPacket pckt = new StealthNetPacket();
        StealthNetComms snComms;
        String iAddr, fName;
        Integer iPort;

        stealthTimer.stop();

        try {
            // check for message from server
            while (stealthComms.recvReady()) {
                pckt = stealthComms.recvPacket();
                switch (pckt.command) {
                    case StealthNetPacket.CMD_MSG :
                	    msgTextBox.append(new String(pckt.data) + "\n");
                        break;

                    case StealthNetPacket.CMD_CHAT:
                        iAddr = new String(pckt.data);
                        iAddr = iAddr.substring(iAddr.lastIndexOf("@") + 1);
                        iPort = new Integer(iAddr.substring(iAddr.lastIndexOf(":") + 1));
                        iAddr = iAddr.substring(0, iAddr.lastIndexOf(":"));
                        snComms = new StealthNetComms();
                        snComms.initiateSession(new Socket(iAddr, iPort.intValue()));
                        new StealthNetChat(userID, snComms).start();
                        break;

                    case StealthNetPacket.CMD_FTP:
                        iAddr = new String(pckt.data);
                        iAddr = iAddr.substring(iAddr.lastIndexOf("@") + 1);
                        fName = iAddr.substring(iAddr.lastIndexOf("#") + 1);
                        iAddr = iAddr.substring(0, iAddr.lastIndexOf("#"));
                        iPort = new Integer(iAddr.substring(iAddr.lastIndexOf(":") + 1));
                        iAddr = iAddr.substring(0, iAddr.lastIndexOf(":"));

                        snComms = new StealthNetComms();
                        snComms.initiateSession(new Socket(iAddr, iPort.intValue()));

                        FileDialog fileSave = new FileDialog(clientFrame, "Save As...", FileDialog.SAVE);
                        fileSave.setFile(fName);
                        fileSave.setVisible(true);
                        if ((fileSave.getFile() != null) && (fileSave.getFile().length() > 0)) {
                            new StealthNetFileTransfer(snComms, fileSave.getDirectory() + fileSave.getFile(), false).start();
                        }
                        break;

                    case StealthNetPacket.CMD_LIST:
                        int indx;
                        String row;
                        String userTable = new String(pckt.data);
                        buddyListData.setRowCount(0);
                        
                        while (userTable.length() > 0) {
                            indx = userTable.indexOf("\n");
                            
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
                        
                        while (secretTable.length() > 0) {
                            indx = secretTable.indexOf("\n");
                            
                            if (indx > 0) {
                                row = secretTable.substring(0, indx);
                                secretTable = secretTable.substring(indx + 1);
                            } else {
                                row = secretTable;
                                secretTable = "";
                            }
                            
                            String values[] = row.split(";");
                            secretListData.addRow(values);
                            
                            SecretData data = new SecretData();
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

						snComms = new StealthNetComms();
						snComms.initiateSession(new Socket(iAddr, iPort.intValue()));

						msgTextBox.append("[INFO] Sending out a secret.\n");

						new StealthNetFileTransfer(snComms,	fName, true).start();

						break;

                    default :
                        System.out.println("unrecognised command");
               }
            }
        } catch (Exception e) {
            System.err.println("error running client thread");
            e.printStackTrace();
        }
        
        stealthTimer.start();
    }

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
        } catch (Exception e) {}

        // create the top-level container and contents
        clientFrame = new JFrame("stealthnet");
        StealthNetClient app = new StealthNetClient();
        Component contents = app.createGUI();
        clientFrame.getContentPane().add(contents, BorderLayout.CENTER);

        // finish setting up the GUI
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