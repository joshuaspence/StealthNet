/* @formatter:off */
/******************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PACKAGE:         StealthNet.Security
 * FILENAME:        EncrpytedFileException.java
 * AUTHORS:         Joshua Spence
 * DESCRIPTION:     An exception to be thrown when an error occurs whilst 
 * 					attempting to an encrypted file.
 *
 *****************************************************************************/
/* @formatter:on */

package StealthNet.Security;

import StealthNet.EncryptedFile;

/* Import Libraries ******************************************************** */

/* StealthNet.Security.EncrpytedFileException Class Definition ************* */

/**
 * An exception to be thrown when an encrypted file cannot be decrypted. <p> An
 * encrypted file may be unable to be decrypted because either the supplied
 * password is incorrect, or the file has been corrupted. It can, in some
 * situations, be difficult to differentiate these two cases.
 * 
 * @author Joshua Spence
 * @see Exception
 * @see EncryptedFile
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
