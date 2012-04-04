package StealthNet;

/**
 * Calculates a verifies packet checksums. This is used to ensure packet 
 * integrity between hosts.
 * 
 * @author Joshua Spence
 */
public class StealthNetChecksum {
	/** 
	 * Set to true in build.xml to output debug messages for this class. 
	 * Alternatively, use the argument `-Ddebug.StealthNetChecksum=true' at the 
	 * command line.
	 */
	private static final boolean DEBUG = true && System.getProperty("debug.StealthNetChecksum", "false").equals("true");
	
	/**
	 * Calculates the checksum for a given message.
	 * 
	 * @param message The message to calculate the checksum for.
	 * @return The checksum of the given message.
	 */
	public byte[] createChecksum(String message) {
		if (DEBUG) System.out.println("Creating checksum for message \"" + message + "\".");
		
		/** TODO */
		
		return message.getBytes();
	}
	
	/**
	 * Calculates the checksum for a given message.
	 * 
	 * @param message The message to calculate the checksum for.
	 * @return The checksum of the given message.
	 */
	public byte[] createChecksum(byte[] message) {
		if (DEBUG) System.out.println("Creating checksum for message \"" + new String(message) + "\".");
		
		/** TODO */
		
		return message;
	}
	
	/**
	 * Verifies a given message against a given checksum
	 * 
	 * @param message The message to check.
	 * @param checksum The given checksum.
	 * 
	 * @return True if the message matches the given checksum, otherwise false.
	 */
	public boolean verifyChecksum(String message, byte[] checksum) {
		if (DEBUG) System.out.println("Verifying checksum \"" + new String(checksum) + "\" for message \"" + new String(message) + "\".");
		
		/** TODO */
		
		return true;
	}
	
	/**
	 * Verifies a given message against a given checksum
	 * 
	 * @param message The message to check.
	 * @param checksum The given checksum.
	 * 
	 * @return True if the message matches the given checksum, otherwise false.
	 */
	public boolean verifyChecksum(byte[] message, byte[] checksum) {
		if (DEBUG) System.out.println("Verifying checksum \"" + new String(checksum) + "\" for message \"" + new String(message) + "\".");
		
		/** TODO */
		
		return true;
	}
}
