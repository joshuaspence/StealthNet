package StealthNet;

public class StealthNetPRNG {
	final int seed;
	Integer next;
	
	public StealthNetPRNG(int s) {
		seed = s;
		next = null;
	}
	
	public int getNextSequenceNumber() {
		if (next != null)
			return next.intValue();
		else
			/** TODO: get next sequence number from PRNG. */
			return 0;
	}
	
	public boolean isExpectedSequenceNumber(int s) {
		if (next != null) 
			next = getNextSequenceNumber();
			
		if (s == next.intValue()) {
			next = getNextSequenceNumber();
			return true;
		}
			
		return false;
	}
}
