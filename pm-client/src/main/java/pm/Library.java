package pm;

import java.security.*;
import java.security.cert.X509Certificate;

public class Library {

	public void init(char[] password, String alias, KeyStore... ks) {
		CreateKey ck = new CreateKey();
		if (ks.length == 0) {
			try {
				ck.generateKeyPair(password, alias);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		ck.verifyKeyStore();

	}

	public void register_user() {
	}

	public void save_password(byte[] domain, byte[] username, byte[] password) {
	}

	public byte[] retrieve_password(byte[] domain, byte[] username) {
		return null;
	}

	public void close() {
	}
}
