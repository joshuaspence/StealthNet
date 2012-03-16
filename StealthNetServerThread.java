/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Stephen Gould, Matt Barrie and Ryan Junee
 *
 * PROJECT:         StealthNet
 * FILENAME:        StealthNetServerThread.java
 * AUTHORS:         Stephen Gould, Matt Barrie, Ryan Junee
 * DESCRIPTION:     Implementation of StealthNet Server for ELEC5616
 *                  programming assignment.
 *                  This code has been written for the purposes of teaching
 *                  cryptography and computer security. It is to be used as
 *                  a demonstration only. No attempt has been made to optimise
 *                  the source code.
 * VERSION:         1.0
 *
 * REVISION HISTORY:
 *
 *****************************************************************************/

/* Import Libraries **********************************************************/

import java.io.*;
import java.net.*;
import java.util.*;

/* StealthNetServerThread Class Definition ***********************************/

public class StealthNetServerThread extends Thread {
    private class UserData {
        StealthNetServerThread userThread = null;
    }

	private class SecretData {
		String name = null;
        String description = null;
        int cost = 0;
        String owner = null;			// Server knows, but clients should not
		String dirname = null;
		String filename = null;
    }

    static private Hashtable userList = new Hashtable();
    static private Hashtable secretList = new Hashtable();
    
    private String userID = null;
    private StealthNetComms stealthComms = null;

    public StealthNetServerThread(Socket socket) {
        super("StealthNetServerThread");
        stealthComms = new StealthNetComms();
        stealthComms.acceptSession(socket);
    }

    protected void finalise() throws IOException {
        if (stealthComms != null)
            stealthComms.terminateSession();
    }

    private synchronized boolean addUser(String id) {
        UserData userInfo = (UserData)userList.get(id);
        if ((userInfo != null) && (userInfo.userThread != null))
            return false;
        userInfo = new UserData();
        userInfo.userThread = this;
        userList.put(id, userInfo);
        return true;
    }

    private synchronized boolean addSecret(SecretData t) {
        SecretData secretInfo = (SecretData)secretList.get(t.name);
        if (secretInfo != null)
            return false;

        secretList.put(t.name, t);
        return true;
    }
    
    private synchronized boolean removeUser(String id) {
        UserData userInfo = (UserData)userList.get(id);
        if (userInfo != null) {
            userInfo.userThread = null;
            return true;
        }
        return false;
    }

    private synchronized boolean removeSecret(String name) {
    	secretList.remove(name);
    	return true;
    }
    
    private synchronized String userListAsString() {
        String userKey, userTable;
        UserData userInfo;

        userTable = "";
        Enumeration i = userList.keys();
        while (i.hasMoreElements()) {
            userKey = (String)i.nextElement();
            userInfo = (UserData)userList.get(userKey);
            userTable += userKey + ", ";
            if ((userInfo != null) && (userInfo.userThread != null)) {
                userTable += "true";
            } else {
                userTable += "false";
            }
            userTable += "\n";
        }

        return userTable;
    }

    private synchronized String secretListAsString() {
        String secretKey, secretTable;
        SecretData secretInfo;

        secretTable = "";
        Enumeration i = secretList.keys();
        while (i.hasMoreElements()) {
            secretKey = (String)i.nextElement();
            secretInfo = (SecretData)secretList.get(secretKey);
            secretTable += secretKey + ";";
            if (secretInfo != null) {
                secretTable += secretInfo.cost + ";";
				secretTable += secretInfo.description + ";";
				secretTable += secretInfo.filename;                
            }
            secretTable += "\n";
        }

        return secretTable;
    }
    private synchronized void sendUserList() {
        String userKey;
        UserData userInfo;

        Enumeration i = userList.keys();
        String userTable = userListAsString();
        while (i.hasMoreElements()) {
            userKey = (String)i.nextElement();
            userInfo = (UserData)userList.get(userKey);
            if ((userInfo != null) && (userInfo.userThread != null)) {
                if (userInfo.userThread.stealthComms == null) {
                    userInfo.userThread = null;
                } else {
                    userInfo.userThread.stealthComms.sendPacket(
                        StealthNetPacket.CMD_LIST, userTable);
                }
            }
        }
    }

    private synchronized void sendSecretList() {
        String userKey;
        UserData userInfo;

        Enumeration i = userList.keys();
        String secretTable = secretListAsString();
        while (i.hasMoreElements()) {
            userKey = (String)i.nextElement();
            userInfo = (UserData)userList.get(userKey);
            if ((userInfo != null) && (userInfo.userThread != null)) {
                if (userInfo.userThread.stealthComms == null) {
                    userInfo.userThread = null;
                } else {
                    userInfo.userThread.stealthComms.sendPacket(
                    	StealthNetPacket.CMD_SECRETLIST, secretTable);
                }
            }
        }
    }

    public void run() {
        String userKey, iAddr;
        UserData userInfo;
        StealthNetPacket pckt = new StealthNetPacket();

        try {
            while (pckt.command != StealthNetPacket.CMD_LOGOUT) {
                pckt = stealthComms.recvPacket();
                switch (pckt.command) {
                case StealthNetPacket.CMD_NULL :
                    System.out.println("received NULL command");
                    break;

                case StealthNetPacket.CMD_LOGIN :
                    if (userID != null) {
                        System.out.println("user " + userID + " trying to log in twice");
                        break;
                    }
                    userID = new String(pckt.data);
                    if (!addUser(userID)) {
                        System.out.println("user \"" + userID + "\" is already logged in");
                        pckt.command = StealthNetPacket.CMD_LOGOUT;
                        userID = null;
                    } else {
                        System.out.println("user \"" + userID + "\" has logged in");
                        sendUserList();
	                    sendSecretList();
                    }
                    break;

                case StealthNetPacket.CMD_LOGOUT :
                    if (userID == null) {
                        System.out.println("unknown user trying to log out");
                        break;
                    }
                    System.out.println("user \"" + userID + "\" has logged out");
                    break;

                case StealthNetPacket.CMD_MSG :
                    if (userID == null) {
                        System.out.println("unknown user trying to send message");
                        break;
                    }
                    String msg = new String(pckt.data);
                    msg = "[" + userID + "] " + msg;
                    Enumeration i = userList.keys();
                    while (i.hasMoreElements()) {
                        userKey = (String)i.nextElement();
                        userInfo = (UserData)userList.get(userKey);
                        if ((userInfo != null) && (userInfo.userThread != null)) {
                            userInfo.userThread.stealthComms.sendPacket(
                                StealthNetPacket.CMD_MSG, msg);
                        }
                    }
                    break;

                case StealthNetPacket.CMD_CHAT :
                    if (userID == null) {
                        System.out.println("unknown user trying to chat");
                        break;
                    }
                    userKey = new String(pckt.data);
                    iAddr = userKey.substring(userKey.lastIndexOf("@") + 1);
                    userKey = userKey.substring(0, userKey.length() - iAddr.length() - 1);
                    userInfo = (UserData)userList.get(userKey);

                    if ((userInfo == null) || (userInfo.userThread == null)) {
                        stealthComms.sendPacket(StealthNetPacket.CMD_MSG,
                            "[*SVR*] user not logged in");
                    } else if (userInfo.userThread == Thread.currentThread()) {
                        stealthComms.sendPacket(StealthNetPacket.CMD_MSG,
                            "[*SVR*] cannot chat to self");
                    } else {
                        userInfo.userThread.stealthComms.sendPacket(
                            StealthNetPacket.CMD_CHAT, userID + "@" + iAddr);
                    }
                    break;

                case StealthNetPacket.CMD_FTP :
                    if (userID == null) {
                        System.out.println("unknown user trying to transfer file");
                        break;
                    }
                    userKey = new String(pckt.data);
                    iAddr = userKey.substring(userKey.lastIndexOf("@") + 1);
                    userKey = userKey.substring(0, userKey.length() - iAddr.length() - 1);
                    userInfo = (UserData)userList.get(userKey);

                    if ((userInfo == null) || (userInfo.userThread == null)) {
                        stealthComms.sendPacket(StealthNetPacket.CMD_MSG,
                            "[*SVR*] user not logged in");
                    } else if (userInfo.userThread == Thread.currentThread()) {
                        stealthComms.sendPacket(StealthNetPacket.CMD_MSG,
                            "[*SVR*] cannot ftp to self");
                    } else {
                        userInfo.userThread.stealthComms.sendPacket(
                            StealthNetPacket.CMD_FTP, userID + "@" + iAddr);
                    }
                    break;

                case StealthNetPacket.CMD_CREATESECRET :
                    if (userID == null) {
                    	System.out.println("unknown user trying to create secret");
                        break;
                    }
                                       
                    // depacketise the create command
                    SecretData t = new SecretData();
                    t.owner = userID;
                    t.name = "";
                    t.description = "";
					t.cost = 0;
					t.dirname = "";
					t.filename = "";
                    
                    
                    StringTokenizer tokens = new StringTokenizer (new String(pckt.data),";");
                    t.name = tokens.nextToken();
                    t.description = tokens.nextToken();
                    t.cost = Integer.parseInt(tokens.nextToken());
					t.dirname = tokens.nextToken();
					t.filename = tokens.nextToken();
                    
                    System.out.println("Added secret.\n");
                    addSecret(t);                    
                    
                    System.out.println("Sending secret list from server.\n");
                    sendSecretList();

                    
                    break;

				case StealthNetPacket.CMD_GETSECRET :
					if (userID == null) {
						System.out.println("unknown user trying to transfer file");
						break;
					}
					String data = new String(pckt.data);
					iAddr =  data.substring(data.lastIndexOf("@") + 1);
					String name = data.substring(0, data.length() - iAddr.length() - 1);
					
					SecretData secretInfo = (SecretData)secretList.get(name);
					if (secretInfo == null) {
						stealthComms.sendPacket(StealthNetPacket.CMD_MSG,
							"[*SVR*] Secret is not available");
						break;
					}
					
					String user = secretInfo.owner;
					userInfo = (UserData)userList.get(user);

					if ((userInfo == null) || (userInfo.userThread == null)) {
						stealthComms.sendPacket(StealthNetPacket.CMD_MSG,
							"[*SVR*] Secret is not currently available");
					} else if (userInfo.userThread == Thread.currentThread()) {
						stealthComms.sendPacket(StealthNetPacket.CMD_MSG,
							"[*SVR*] You can't purchase a secret from yourself!");
					} else {
						String fName = secretInfo.dirname + secretInfo.filename;
						userInfo.userThread.stealthComms.sendPacket(
							StealthNetPacket.CMD_GETSECRET, fName + "@" + iAddr);
					}

					break;

                default :
                    System.out.println("unrecognised command");
                }
            }
        } catch (IOException e) {
            System.out.println("user \"" + userID + "\" session terminated");
        } catch (Exception e) {
            System.err.println("Error running server thread");
            e.printStackTrace();
        }

        if (userID != null)
            removeUser(userID);
        sendUserList();

        if (stealthComms != null) {
            stealthComms.terminateSession();
            stealthComms = null;
        }
    }
}

/******************************************************************************
 * END OF FILE:     StealthNetServerThread.java
 *****************************************************************************/
 
