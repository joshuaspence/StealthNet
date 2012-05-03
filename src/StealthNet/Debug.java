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
	 * If set to <pre>new Boolean(true)<pre> then all calls to
	 * <pre>isDebug</pre> will automatically return true. If set to <pre>new
	 * Boolean(false)</pre> then all calls to <pre>isDebug</pre> will
	 * automatically return false. If set to <pre>null</pre>, then
	 * <pre>isDebug</pre> will proceed as intended.
	 */
	private static final Boolean overwriteResult = null;
	
	private static final String DEBUG_PREFIX = "debug";
	private static final String DELIMITER = ".";
	
	private static final String FALSE_STRING = "false";
	private static final String TRUE_STRING = "true";
	
	/**
	 * Checks if debug output should be enabled for a given function. For
	 * example: <pre>isDebug("StealthNet.Client.Commands.FTP")</pre> will return
	 * true if any of the following are defined to be true at the command line
	 * (using <pre>-Dxxx=true</pre>): <pre>debug</pre>,
	 * <pre>debug.StealthNet.</pre>, <pre>debug.StealthNet.Client</pre>,
	 * <pre>debug.StealthNet.Client.Commands</pre>,
	 * <pre>debug.StealthNet.Client.Commands.FTP</pre>.
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
			
			/** Check if we are done. */
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
