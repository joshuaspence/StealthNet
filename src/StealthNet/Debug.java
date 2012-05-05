/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet
 * FILENAME:        Debug.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     Command-line debug functionality for StealthNet.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet;

/* Import Libraries ******************************************************** */

import java.util.ArrayList;
import java.util.Arrays;

/* StealthNet.Debug Class Definition *************************************** */

/**
 * A simple class for providing debug functionality and the ability to turn
 * on/off debug functionality from the command line.
 * 
 * @author Joshua Spence
 */
public class Debug {
	/**
	 * If set to <code>new Boolean(true)</code> then all calls to
	 * <code>isDebug</code> will automatically return true. If set to <code>new
	 * Boolean(false)</code> then all calls to <code>isDebug</code> will
	 * automatically return false. If set to <code>null</code>, then
	 * <code>isDebug</code> will proceed as intended.
	 */
	private static final Boolean overwriteResult = null;
	
	private static final String DEBUG_PREFIX = "debug";
	private static final String DELIMITER = ".";
	
	private static final String FALSE_STRING = "false";
	private static final String TRUE_STRING = "true";
	
	/**
	 * Checks if debug output should be enabled for a given function. For
	 * example: <code>isDebug("StealthNet.Client.Commands.FTP")</code> will
	 * return true if any of the following are defined to be true at the command
	 * line (using <code>-Dxxx=true</code>): <code>debug</code>,
	 * <code>debug.StealthNet.</pre>, <code>debug.StealthNet.Client</code>,
	 * <code>debug.StealthNet.Client.Commands</code>,
	 * <code>debug.StealthNet.Client.Commands.FTP</code>.
	 * 
	 * @param s The function to check for debug functionality.
	 * @return True if debug functionality should be enabled, otherwise false.
	 */
	public static boolean isDebug(final String s) {
		if (overwriteResult != null)
			return overwriteResult.booleanValue();
		
		String propertyString = DEBUG_PREFIX;
		final ArrayList<String> sections = new ArrayList<String>(Arrays.asList(s.split("\\" + DELIMITER)));
		
		while (true) {
			if (System.getProperty(propertyString, FALSE_STRING).equals(TRUE_STRING))
				return true;
			
			/* Check if we are done. */
			if (sections.size() <= 0)
				break;
			
			propertyString = propertyString.concat(DELIMITER + sections.get(0));
			sections.remove(0);
		}
		
		return false;
	}
}

/******************************************************************************
 * END OF FILE: Debug.java
 *****************************************************************************/
