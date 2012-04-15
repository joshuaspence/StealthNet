/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie and Stephen Gould
 *
 * PROJECT:         StealthNet
 * FILENAME:        StealthNetDebug.java
 * AUTHORS:         Joshua Spence and Ahmad Al Mutawa
 * DESCRIPTION:     Command-line debug functionality for StealthNet.
 * VERSION:         1.0
 *
 *****************************************************************************/

package StealthNet;

/* Import Libraries **********************************************************/

import java.util.ArrayList;
import java.util.Arrays;

/* StealthNetDebug Class Definition *******************************************/

/**
 * A simple class for providing debug functionality and the ability to turn 
 * on/off debug functionality from the command line.
 * 
 * @author Joshua Spence
 */
public class StealthNetDebug {
	@SuppressWarnings("unused")
	private static final Boolean overwriteResultFalse = new Boolean(false);
	@SuppressWarnings("unused")
	private static final Boolean overwriteResultTrue = new Boolean(true);
	private static final Boolean overwriteResult = null;
	
	private static final String DEBUG_PREFIX = "debug";
	private static final String DELIMITER = ".";
	
	private static final String FALSE_STRING = "false";
	private static final String TRUE_STRING = "true";
	
	/**
	 * Checks if debug output should be enabled for a given function.
	 * 
	 * @param s The function to check for debug functionality.
	 * @return True if debug functionality should be enabled, otherwise false.
	 */
	public static boolean isDebug(String s) {
		if (overwriteResult != null)
			return overwriteResult.booleanValue();
		
		String propertyString = DEBUG_PREFIX;
		final ArrayList<String> sections = new ArrayList<String>(Arrays.asList(s.split("\\" + DELIMITER)));
		
		while (true) {
			if (System.getProperty(propertyString, FALSE_STRING).equals(TRUE_STRING))
				return true;
			
			if (sections.size() <= 0)
				break;
			
			propertyString = propertyString.concat(DELIMITER + sections.get(0));
			sections.remove(0);
		}
		
		return false;
	}
}
