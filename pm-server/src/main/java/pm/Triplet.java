package pm;

import java.io.Serializable;
import java.util.ArrayList;

public class Triplet implements Serializable {

	private static final long serialVersionUID = 1L;

	private byte[] domain;
	private byte[] username;
	private byte[] password;
	private byte[] salt;
	private byte[] timestamp;
	private ArrayList<byte[]> signturesArray = new ArrayList<byte[]>();
	private byte[] valueSignature;
	private byte[] writeRank;

	public Triplet(byte[] domain, byte[] username, byte[] password, byte[] salt, byte[] timestamp, byte[] writeRank,
			byte[] valueSignature, byte[] signature) {
		this.setDomain(domain);
		this.setUsername(username);
		this.setPassword(password);
		this.setSalt(salt);
		this.setTimestamp(timestamp);
		this.setValueSignature(valueSignature);
		this.setWriteRank(writeRank);
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

	public byte[] getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(byte[] timestamp) {
		this.timestamp = timestamp;
	}

	public ArrayList<byte[]> getSignturesArray() {
		return signturesArray;
	}

	public void addSignturesArray(byte[] signtures) {
		getSignturesArray().add(signtures);
	}

	public byte[] getValueSignature() {
		return valueSignature;
	}

	public void setValueSignature(byte[] valueSignature) {
		this.valueSignature = valueSignature;
	}

	public byte[] getWriteRank() {
		return writeRank;
	}

	public void setWriteRank(byte[] writeRank) {
		this.writeRank = writeRank;
	}

}
