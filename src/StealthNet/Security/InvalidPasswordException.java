/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        InvalidPasswordException.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     An exception to be thrown when the wrong password is used 
 * 					for decryption.
 *
 *****************************************************************************/

package StealthNet.Security;

/* Import Libraries **********************************************************/

/* StealthNet.Security.InvalidPasswordException Class Definition *************/

/**
 * An exception to be thrown when the wrong password is used for decryption.
 * 
 * @author Joshua Spence
 */
public class InvalidPasswordException extends Exception {
	private static final long serialVersionUID = 1L;

	/** 
	 * Constructor
	 * @param msg A message describing the exception.
	 */
	public InvalidPasswordException(String msg) {
		super(msg);
	}
}

/******************************************************************************
 * END OF FILE:     InvalidPasswordException.java
 *****************************************************************************/