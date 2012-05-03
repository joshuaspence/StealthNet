/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        EncrpytedFileException.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     An exception to be thrown when an error occurs whilst 
 * 					decrypting an encrypted file.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet.Security;

/* Import Libraries ******************************************************** */

/* StealthNet.Security.EncrpytedFileException Class Definition ************* */

/**
 * An exception to be thrown when an encrypted file cannot be decrypted.
 * 
 * @author Joshua Spence
 */
public class EncryptedFileException extends Exception {
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor.
	 * 
	 * @param msg A message describing the exception.
	 */
	public EncryptedFileException(final String msg) {
		super(msg);
	}
}

/******************************************************************************
 * END OF FILE: EncrpytedFileException.java
 *****************************************************************************/
