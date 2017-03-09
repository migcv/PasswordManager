package pm.exception;

public class PublicKeyDoesntExistException extends RuntimeException {

	private static final long serialVersionUID = 1L;
	
	public String getMessage() {
		return "Public key doesnt exists";
	}

}
