package StealthNet;

public class StealthNetChecksum {
	/** 
	 * Set to true in build.xml to output debug messages for this class. 
	 * Alternatively, use the argument `-Ddebug.StealthNetChecksum=true' at the 
	 * command line.
	 */
	@SuppressWarnings("unused")
	private static final boolean DEBUG = System.getProperty("debug.StealthNetChecksum", "false").equals("true");
	
	public StealthNetChecksum() {}
	
	public byte[] createChecksum(byte[] message) {
		/** TODO */
		return message;
	}
	
	public boolean verifyChecksum(byte[] message, byte[] checksum) {
		/** TODO */
		return true;
	}
}
