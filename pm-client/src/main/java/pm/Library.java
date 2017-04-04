package pm;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;

public class Library {

	protected static int N = 10;
	protected static int PORT = 10000;

	private ArrayList<Thread> threadArray = new ArrayList<Thread>(N);
	private int requestID = 0;
	public Object[] request = null;

	public Library() {
		for (int i = 0; i < N; i++) {
			Thread td = new Thread(new LibraryThread(PORT + i, this), Integer.toString(PORT + i));
			td.start();
			threadArray.add(td);
		}
		
	}

	public void init(char[] password, String alias, KeyStore ks) {
		
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

	private void connectToServer() {
	}

	public KeyStore getInstanceOfKeyStore(char[] password, String alias) {
		// Create an instance of KeyStore of type “JCEKS”
		KeyStore ks = null;
		try {
			// Open the KeyStore file
			FileInputStream fis = new FileInputStream("keystorefile" + alias + ".jce");
			ks = KeyStore.getInstance("JCEKS");
			// Load the key entries from the file into the KeyStore object.
			ks.load(fis, password);
			fis.close();
		} catch (FileNotFoundException e) {
			return null;
		} catch (KeyStoreException e) {
			return null;
		} catch (NoSuchAlgorithmException e) {
			return null;
		} catch (CertificateException e) {
			return null;
		} catch (IOException e) {
			return null;
		}
		return ks;
	}

}
