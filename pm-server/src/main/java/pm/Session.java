package pm;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.Key;

import javax.crypto.SecretKey;

public class Session implements Serializable {

	private static final long serialVersionUID = 1L;

	private Key pubKey;
	private SecretKey sessionKey;
	private BigInteger nounce;

	public Session(Key pubKey, SecretKey sessionKey, BigInteger nounce) {
		super();
		this.pubKey = pubKey;
		this.sessionKey = sessionKey;
		this.nounce = nounce;
	}

	public BigInteger getNounce() {
		return nounce;
	}

	public void setNounce(BigInteger nounce) {
		this.nounce = nounce;
	}

	public Key getPubKey() {
		return pubKey;
	}

	public SecretKey getSessionKey() {
		return sessionKey;
	}

}
