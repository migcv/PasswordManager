package pm.exception;

public class InvalidTimestampException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public String getMessage() {
		return "Invalid Timestap";
	}
}