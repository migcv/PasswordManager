package pm;

import java.io.Serializable;

public class Triplet  implements Serializable{

	private static final long serialVersionUID = 1L;
	
	private byte[] domain;
	private byte[] username;
	private byte[] password;
	
	private byte[] salt;

	public Triplet(byte[] domain, byte[] username, byte[] password, byte[] salt) { 
		// guardar a assinatura de tudo para garantir nao repudio toto
		this.setDomain(domain);
		this.setUsername(username);
		this.setPassword(password);
		this.setSalt(salt);
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

	public byte[] getSalt() {
		return salt;
	}

	public void setSalt(byte[] salt) {
		this.salt = salt;
	}
	
}
