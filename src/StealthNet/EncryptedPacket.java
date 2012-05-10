/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie, Stephen Gould and Ryan Junee
 *
 * PACKAGE:         StealthNet
 * FILENAME:        EncryptedPacket.java
 * AUTHORS:         Matt Barrie, Stephen Gould, Ryan Junee and Joshua Spence
 * DESCRIPTION:     Implementation of a StealthNet packet. This class represents
 * 					encrypted packet contents.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet;

/* Import Libraries ******************************************************** */

import java.io.UnsupportedEncodingException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.management.InvalidAttributeValueException;

import org.apache.commons.codec.binary.Base64;

import StealthNet.Security.Encryption;
import StealthNet.Security.HashedMessageAuthenticationCode;
import StealthNet.Security.MessageAuthenticationCode;

/* StealthNet.Packet Class Definition ************************************** */

/**
 * A class to store the encrypted data passed between StealthNet {@link Client}
 * s. An encrypted StealthNet packet consists of two parts: <ul> <li>data
 * (encrypted)</li> <li> digest</li> </ul>
 * 
 * <p> To avoid the need to transmit the length of the data field, we ensure
 * that the length of the digest field is fixed, and known by the {@link Client}
 * s.
 * 
 * <p> A message digest is produced by passing a
 * {@link MessageAuthenticationCode} instance to the relevant function. This
 * class will allow encrypted packets to be created without a digest (if a null
 * {@link MessageAuthenticationCode} instance is passed to the function, for
 * instance). A higher layer should check whether or not this should be allowed.
 * 
 * <p> The data contained in this class does not necessarily have to be
 * encrypted, it could simply be the same data that was contained in the
 * corresponding {@link DecryptedPacket} class. However, {@link EncryptedPacket}
 * s are the only packets that are actually transmitted over the communications
 * channel.
 * 
 * @author Matt Barrie
 * @author Stephen Gould
 * @author Ryan Junee
 * @author Joshua Spence
 * 
 * @see DecryptedPacket
 * @see MessageAuthenticationCode
 */
public class EncryptedPacket {
	/** The (usually encrypted) data being sent in the packet. */
	final byte data[];
	
	/**
	 * The {@link MessageAuthenticationCode} digest of the packet data, encoded
	 * in base-64
	 * 
	 * @see Base64
	 */
	final byte digest[];
	
	/**
	 * The (fixed) length of the digest field, to avoid having to transmit the
	 * length of the data field, which complicates decryption, especially in the
	 * case of modified packet data.
	 */
	private static final int digestBytes = HashedMessageAuthenticationCode.DIGEST_BYTES;
	
	/** Null constructor. */
	public EncryptedPacket() {
		/** No data is available. */
		data = new byte[0];
		
		/** No digest is available. */
		digest = new byte[digestBytes];
	}
	
	/**
	 * Constructor with no {@link MessageAuthenticationCode} digest. Explicitly
	 * copies the data array contents.
	 * 
	 * @param encryptedData The (usually encrypted) data to be sent in the
	 *        packet.
	 */
	public EncryptedPacket(final byte[] encryptedData) {
		if (encryptedData == null)
			data = new byte[0];
		else {
			data = new byte[encryptedData.length];
			System.arraycopy(encryptedData, 0, data, 0, encryptedData.length);
		}
		
		/* No digest is available. */
		digest = new byte[digestBytes];
	}
	
	/**
	 * Constructor with {@link MessageAuthenticationCode} digest. Explicitly
	 * copies the data array contents.
	 * 
	 * @param encryptedDataLen The length of the <code>encryptedData</code>
	 *        array.
	 * @param encryptedData The data to be sent in the packet.
	 * @param mac The {@link MessageAuthenticationCode} instance to provide a
	 *        MAC digest. If null, then the digest will be blank.
	 * 
	 * @throws IllegalArgumentException
	 * @throws InvalidAttributeValueException
	 */
	public EncryptedPacket(final byte[] encryptedData, final int encryptedDataLen, final MessageAuthenticationCode mac) throws IllegalArgumentException, InvalidAttributeValueException {
		/* Copy the data. */
		if (encryptedData == null)
			data = new byte[0];
		else {
			data = new byte[encryptedDataLen];
			System.arraycopy(encryptedData, 0, data, 0, encryptedDataLen);
		}
		
		/* Create the MAC digest (if possible). */
		if (mac == null)
			digest = new byte[digestBytes];
		else {
			digest = mac.createMAC(data);
			
			if (digest.length != digestBytes)
				throw new IllegalArgumentException("Specified digest size does not equal to actual digest size. Specified size: " + digestBytes + ". Actual size: " + digest.length + ".");
		}
	}
	
	/**
	 * Constructor. This function must "undo" the effects of the
	 * <code>toString()</code> function, because this function converts the
	 * received data into a packet at the receiving end of communications.
	 * 
	 * @param str A {@link String} consisting of the packet contents.
	 */
	public EncryptedPacket(String str) {
		/*
		 * Add padding if necessary, to make the packet length an integer number
		 * of bytes (each represented by HEX_PER_BYTE hexadecimal characters).
		 */
		while (str.length() % Utility.HEX_PER_BYTE != 0)
			str = "0" + str;
		
		if (str.length() == 0) {
			/* NULL packet. */
			data = new byte[0];
			digest = new byte[digestBytes];
		} else {
			/* Current index of the string. */
			int current = 0;
			
			/* Data length. */
			final int dataLen = str.length() / Utility.HEX_PER_BYTE - digestBytes;
			
			/* Data (dataLen bytes). */
			data = new byte[dataLen];
			for (int i = 0; i < data.length; i++)
				data[i] = (byte) (16 * Utility.singleHexToInt(str.charAt(current++)) + Utility.singleHexToInt(str.charAt(current++)));
			
			/* Digest (digestBytes bytes). */
			digest = new byte[digestBytes];
			for (int i = 0; i < digest.length; i++)
				digest[i] = (byte) (16 * Utility.singleHexToInt(str.charAt(current++)) + Utility.singleHexToInt(str.charAt(current++)));
		}
	}
	
	/**
	 * Converts the packet to a string. This function must undo the effects of
	 * the <code>EncryptedPacket(String)</code> constructor, because this
	 * function is used to convert a packet to a string for transmission at the
	 * sending end of communications.
	 * 
	 * @return A {@link String} representing the contents of the packet.
	 */
	@Override
	public String toString() {
		String str = "";
		int lowHalfByte, highHalfByte;
		
		/* Data (data.length bytes). */
		for (final byte element : data) {
			highHalfByte = element >= 0 ? element : 256 + element;
			lowHalfByte = highHalfByte & 0xF;
			highHalfByte /= Utility.HEXTABLE.length;
			str += Utility.HEXTABLE[highHalfByte];
			str += Utility.HEXTABLE[lowHalfByte];
		}
		
		/* Digest (digest.length bytes). */
		for (final byte element : digest) {
			highHalfByte = element >= 0 ? element : 256 + element;
			lowHalfByte = highHalfByte & 0xF;
			highHalfByte /= Utility.HEXTABLE.length;
			str += Utility.HEXTABLE[highHalfByte];
			str += Utility.HEXTABLE[lowHalfByte];
		}
		
		return str;
	}
	
	/**
	 * Verify a {@link MessageAuthenticationCode} digest by calculating our own
	 * {@link MessageAuthenticationCode} digest of the same data, and comparing
	 * it with the {@link MessageAuthenticationCode} digest stored in the
	 * packet. If the {@link MessageAuthenticationCode} instance is null, then
	 * the verification will pass automatically. Beware that this may not always
	 * be the desired result, so this should be checked at a higher layer.
	 * 
	 * @param mac The {@link MessageAuthenticationCode} instance to calculate
	 *        the {@link MessageAuthenticationCode} digest.
	 * @return True if the digest matches (or if the
	 *         {@link MessageAuthenticationCode} instance is null), otherwise
	 *         false.
	 * 
	 * @throws InvalidAttributeValueException
	 * @see MessageAuthenticationCode
	 */
	public boolean verifyMAC(final MessageAuthenticationCode mac) throws InvalidAttributeValueException {
		if (mac == null)
			return true;
		else
			return mac.verifyMAC(data, digest);
	}
	
	/**
	 * Get a {@link String} representation of the packet. For debug purposes
	 * only.
	 * 
	 * @return A comma-separated {@link String} containing the the value of each
	 *         of the packet's fields. For purely cosmetic purposes, newline
	 *         characters will be replaced by semicolons.
	 */
	public String getEncryptedString() {
		String str = "";
		
		/* Packet data. */
		if (data.length > 0)
			str += new String(data).replaceAll("\n", ";");
		else
			str += "null";
		str += ", ";
		
		/* Packet digest. */
		if (digest.length > 0)
			str += Utility.getHexValue(digest);
		else
			str += "null";
		
		return str;
	}
	
	/**
	 * Decrypt this packet.
	 * 
	 * @param d The {@link Encryption} instance to decrypt the packet. If null,
	 *        then it will be assumed that the packet is not encrypted.
	 * @return The decrypted packet. If parameter d is null, then the
	 *         {@link DecryptedPacket} is identical to the data stored in the
	 *         {@link EncryptedPacket}.
	 * 
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws UnsupportedEncodingException
	 * 
	 * @see Encryption
	 * @see DecryptedPacket
	 */
	public DecryptedPacket decrypt(final Encryption d) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		if (d != null)
			return new DecryptedPacket(new String(d.decrypt(data)));
		else
			return new DecryptedPacket(new String(data));
	}
}

/******************************************************************************
 * END OF FILE: EncryptedPacket.java
 *****************************************************************************/
