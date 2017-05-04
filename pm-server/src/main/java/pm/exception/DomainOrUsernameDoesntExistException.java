package pm.exception;

public class DomainOrUsernameDoesntExistException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public String getMessage() {
		return "Domain and/or username doesnt exists";
	}
}
