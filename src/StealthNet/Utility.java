/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet
 * FILENAME:        Utility.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     Utility functions that are common throughout StealthNet.
 *
 *****************************************************************************/

package StealthNet;

/* Import Libraries **********************************************************/

/* StealthNet.Utility Class Definition ***************************************/

/**
 * Utility functions that are common throughout StealthNet.
 *  
 * @author Stephen Gould
 * @author Matt Barrie
 * @author Ryan Junee
 * @author Joshua Spence
 */
public class Utility {
	/** Hexadecimal characters. */
    public static final char[] HEXTABLE = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    public static final int HEX_PER_BYTE = Byte.SIZE / (int) logBase2(HEXTABLE.length);
    
	/**
     * Function to assist with printing cryptographic keys by returning byte 
     * arrays as a hexadecimal number.
     * 
     * @param array The byte array to transfer into a hexadecimal number.
     * @return The string containing the hexadecimal number.
     */    
    public static String getHexValue(byte[] array) {
		final String hexDigitChars = "0123456789ABCDEF";
		final StringBuffer buf = new StringBuffer(array.length * HEX_PER_BYTE);
		
		for (int cx = 0; cx < array.length; cx++) {
			final int hn = ((int) (array[cx]) & 0x00FF) / HEXTABLE.length;
			final int ln = ((int) (array[cx]) & 0x000F);
			buf.append(hexDigitChars.charAt(hn));
			buf.append(hexDigitChars.charAt(ln));
		}
		
		return buf.toString();
	}
    
    /** 
     * A utility function to convert a single hexadecimal character to a decimal
     * integer.
     * 
     * @param hex The hexadecimal character to convert to an integer.
     * @return The integer value of the hexadecimal character.
     */
    public static int singleHexToInt(char hex) {
             if ((hex >= '0') && (hex <= '9')) return (hex - '0');
        else if ((hex >= 'A') && (hex <= 'F')) return (hex - 'A' + 10);
        else if ((hex >= 'a') && (hex <= 'f')) return (hex - 'a' + 10);
        else return 0;
    }
    
	/**
     * Convert a hexadecimal string to an integer.
     * 
     * @param hex The string to convert.
     * @return An integer representing the hexadecimal string.
     * @throws NumberFormatException
     */
	public static int hexToInt(String hex) throws NumberFormatException {
    	return Integer.parseInt(hex, HEXTABLE.length);
	}
	
	/**
     * Convert an integer to a hexadecimal string. The length of the hexadecimal 
     * string will be equal to the length that would be required to encode
     * Integer.MAX_VALUE as a hexadecimal string.
     * 
     * @param value The integer to convert.
     * @return The hexadecimal string representing the integer.
     */
	public static String intToHex(int value) {
		String result = Integer.toHexString(value);
		
		/** Pad the result to use the full 4 bytes of an integer. */
		while (result.length() < HEX_PER_BYTE * (Integer.SIZE / Byte.SIZE))
			result = "0" + result;
		
		return result;
	}
	
	/**
	 * Find the logarithm of a number in base 2.
	 * 
	 * @param x The number to find the logarithm of.
	 * @return The base-2 logarithm.
	 */
	public static double logBase2(double x) {
		return (Math.log(x) / Math.log(2));
	}
}

/******************************************************************************
 * END OF FILE: Utility.java
 *****************************************************************************/