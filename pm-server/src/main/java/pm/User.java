package pm;

import java.security.Key;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class User {

	private byte[] domain;
	private byte[] username;
	private byte[] password;
	private Key publicKey;
	

	public User(byte[] domain, byte[] username, byte[] password) {
		this.domain = domain;
		this.username = username;
		this.password = password;
	}
	
	private Map<Key, List<User>> publicKeyToUser = new HashMap<Key, List<User>>();

	public Map<Key, List<User>> getPublicKeyToUser() {
		return publicKeyToUser;
	}

	public void setPublicKeyToUser(Map<Key, List<User>> publicKeyToUser) {
		this.publicKeyToUser = publicKeyToUser;
	}
	
}
