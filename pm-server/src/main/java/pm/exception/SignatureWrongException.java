package pm.exception;

public class SignatureWrongException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public String getMessage() {
		return "Wrong Signature";
	}

}
