package pm;

import java.rmi.Naming;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Library {

	private ServerService server = null;
	private KeyManagement ck = new KeyManagement();
	private SecretKey sessionKey = null;

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
			byte[] sessionKeyEncryp = server.init(ck.getPublicK());

			Cipher decipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
			decipher.init(Cipher.DECRYPT_MODE, ck.getPrivateK());
			byte[] aux = decipher.doFinal(sessionKeyEncryp);

			sessionKey = new SecretKeySpec(aux, 0, aux.length, "AES");
		} catch (RemoteException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
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

		byte[] passEncryp = null, domainHash = null, usernameHash = null, aux = null, domainEncry = null,
				usernameEncry = null;

		try {

			// Cipher Password with Public Key
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, ck.getPublicK());
			aux = cipher.doFinal(password);

			// Cipher Password with Session Key
			SecureRandom random = new SecureRandom();
			byte[] iv = new byte[16];
			random.nextBytes(iv);
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			Cipher firstCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			firstCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivspec);
			passEncryp = firstCipher.doFinal(aux);

			// Digest of Domain and Username
			domainHash = ck.digest(domain);
			usernameHash = ck.digest(username);

			// Signature of all data, E( H(domain)), E( H(username)) &
			// E(password)

			domainEncry = firstCipher.doFinal(domainHash);
			usernameEncry = firstCipher.doFinal(usernameHash);

			byte[] signature = ck.signature(domainEncry, usernameEncry, passEncryp);

			server.put(ck.getPublicK(), domainEncry, usernameEncry, passEncryp, iv, signature);

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
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
	}

	public byte[] retrieve_password(byte[] domain, byte[] username) {

		byte[] password = null, domainHash = null, usernameHash = null, aux = null, domainEncryp = null, usernameEncryp = null;
		ArrayList<byte[]> data = new ArrayList<byte[]>();

		try {
			SecureRandom random = new SecureRandom();
			byte[] iv = new byte[16];
			random.nextBytes(iv);
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivspec);
			
			
			// Digest of Domain and Username
			domainHash = ck.digest(domain);
			usernameHash = ck.digest(username);
			
			domainEncryp = cipher.doFinal(domainHash);
			usernameEncryp = cipher.doFinal(usernameHash);
			// Signature of all data, E( H(domain)), E( H(username))
			byte[] signature = ck.signature(domainEncryp, usernameEncryp);

			data = server.get(ck.getPublicK(), domainEncryp, usernameEncryp, iv, signature);

			// Decipher with Session Key
			byte[] passwordCipher = data.get(0);
			iv = data.get(1);
			
			ivspec = new IvParameterSpec(iv);
			
			Cipher firstDecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			firstDecipher.init(Cipher.DECRYPT_MODE, sessionKey, ivspec);
			aux = firstDecipher.doFinal(passwordCipher);

			// Decipher Password with Private Key
			Cipher decipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			decipher.init(Cipher.DECRYPT_MODE, ck.getPrivateK());
			password = decipher.doFinal(aux);

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
		} catch (InvalidAlgorithmParameterException e) {
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
