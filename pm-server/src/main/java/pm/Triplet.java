package pm;

import java.io.Serializable;
import java.util.ArrayList;

public class Triplet implements Serializable {

	private static final long serialVersionUID = 1L;
	
	private byte[] domain;
	private byte[] username;
	private byte[] password;
	private byte[] salt;
	private ArrayList<byte[]> signturesArray = new ArrayList<byte[]>();

	public Triplet(byte[] domain, byte[] username, byte[] password, byte[] salt, byte[] signature) { 
		this.setDomain(domain);
		this.setUsername(username);
		this.setPassword(password);
		this.setSalt(salt);
		addSignturesArray(signature);
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
	
	public ArrayList<byte[]> getSignturesArray() {
		return signturesArray;
	}

	public void addSignturesArray(byte[] signtures) {
		getSignturesArray().add(signtures);
	}
	
}
