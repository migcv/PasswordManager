package pm.exception;

public class InvalidNounceException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public String getMessage() {
		return "Invalid Nounce";
	}
}
