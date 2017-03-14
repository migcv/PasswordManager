package pm;

import java.rmi.Naming;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Library {

	private ServerService server = null;
	private KeyManagement ck = new KeyManagement();
	private Key sessionKey;

	public void init(char[] password, String alias, KeyStore... ks) {
		
		// Initializes a connection to the Server
		connectToServer();
		// Generate a new key pair
		if (ks.length == 0) {
			try {
				ck.generateKeyPair(password, alias);
			} catch (Exception e) {
				e.printStackTrace();
			}
		} 
		// Extracts the key pair
		else {
			try {
				ck.getKeys(ks[0], alias, password);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		try {
			sessionKey = server.init(ck.getPrivateK());
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

	public void register_user() {

		try {
			server.register(ck.getPublicK());
		} catch (RemoteException e) {
			e.printStackTrace();
		}

	}

	public void save_password(byte[] domain, byte[] username, byte[] password) {
		
		byte[] passEncryp = null, domainHash = null, usernameHash = null;

		try {
			// Cipher Password with Public Key
			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, ck.getPublicK());
			passEncryp = cipher.doFinal(password);
			// Digest of Domain and Username
			domainHash = ck.digest(domain);
			usernameHash = ck.digest(username);
			// Signature of all data, H(domain), H(username) & E(password)
			byte[] signature = ck.signature(domainHash, usernameHash, passEncryp);
			
			server.put(ck.getPublicK(), domainHash, usernameHash, passEncryp, signature);
			
		} catch (RemoteException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
	}

	public byte[] retrieve_password(byte[] domain, byte[] username) {
		
		byte[] password = null, domainHash = null, usernameHash = null;
		byte[] passwordEncrypted = null;
		
		try {
			// Digest of Domain and Username
			domainHash = ck.digest(domain);
			usernameHash = ck.digest(username);
			// Signature of all data, H(domain), H(username)
			byte[] signature = ck.signature(domainHash, usernameHash);
			
			passwordEncrypted = server.get(ck.getPublicK(), domainHash, usernameHash, signature);
			
			// Dipher Password with Private Key
			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
			cipher.init(Cipher.DECRYPT_MODE, ck.getPrivateK());
			password = cipher.doFinal(passwordEncrypted);

		} catch (RemoteException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		return password;
	}

	public void close() {
		// It's better to leave it
		// the connection between RMI client and server is implicit.
		// The connection closes after a short idle period of time
		// automatically.
		// RMI's TCP connections are managed invisibly under the hood.
		// Just let the stub be garbage-collected.
	}
	
	private void connectToServer() {
		if (System.getSecurityManager() == null) {
			System.setSecurityManager(new SecurityManager());
		}
		try {
			server = (ServerService) Naming.lookup("//localhost:10000/ServerService");
			System.out.println("Server found!");

		} catch (Exception e) {
			System.out.println("Ups...something is wrong: " + e.getMessage());
		}
	}

}
