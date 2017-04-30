package pm.exception;

public class InconcistencyException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public String getMessage() {
		return "Inconcistency in the values";
	}
}