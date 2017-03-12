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

	private void connectToServer() {
		if (System.getSecurityManager() == null) {
			System.setSecurityManager(new SecurityManager());
		} else
			System.out.println("Já tem um cenas");

		try {

			server = (ServerService) Naming.lookup("//localhost:10000/ServerService");
			System.out.println("Encontrou o servidor");

		} catch (Exception e) {
			System.out.println("Houve problemas: " + e.getMessage());
		}

	}

	public void init(char[] password, String alias, KeyStore... ks) {

		connectToServer();

		if (ks.length == 0) {
			try {
				ck.generateKeyPair(password, alias);
			} catch (Exception e) {
				e.printStackTrace();
			}
		} else {
			try {
				ck.getKeys(ks[0], alias, password);
			} catch (Exception e) {
				e.printStackTrace();
			}
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
		PublicKey pk = ck.getPublicK();
		byte[] passEncryp = null;

		try {
			Cipher cipher = Cipher.getInstance("RSA/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, pk);
			passEncryp = cipher.doFinal(password);
			server.put(ck.getPublicK(), domain, username, passEncryp);
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
		}
	}

	public byte[] retrieve_password(byte[] domain, byte[] username) {
		byte[] passwordEncryp = null;
		byte[] password = null;
		try {

			Cipher cipher = Cipher.getInstance("RSA/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, ck.getPrivateK());
			passwordEncryp = server.get(ck.getPublicK(), domain, username);
			password = cipher.doFinal(passwordEncryp);

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

}
