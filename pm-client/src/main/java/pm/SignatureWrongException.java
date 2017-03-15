package pm;

public class SignatureWrongException extends RuntimeException {

	private static final long serialVersionUID = 1L;
	
	public String getMessage() {
		return "Signature wrong!";
	}

}
