package pm;

import java.io.Serializable;

public class Triplet  implements Serializable{

	private static final long serialVersionUID = 1L;
	
	private byte[] domain;
	private byte[] username;
	private byte[] password;

	public Triplet(byte[] domain, byte[] username, byte[] password) {
		this.setDomain(domain);
		this.setUsername(username);
		this.setPassword(password);
	}

	public byte[] getPassword() {
		return password;
	}

	public void setPassword(byte[] password) {
		this.password = password;
	}

	public byte[] getUsername() {
		return username;
	}

	public void setUsername(byte[] username) {
		this.username = username;
	}

	public byte[] getDomain() {
		return domain;
	}

	public void setDomain(byte[] domain) {
		this.domain = domain;
	}
	
}
