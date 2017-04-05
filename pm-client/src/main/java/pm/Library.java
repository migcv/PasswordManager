package pm;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

public class Library {

	protected static int N = 4;
	protected static int PORT = 10000;

	private ArrayList<Thread> threadArray = new ArrayList<Thread>(N);
	private int requestID = 0;
	private ConcurrentHashMap<Integer, Object[]> request = new ConcurrentHashMap<Integer, Object[]>();
	private boolean end = false;

	private ConcurrentHashMap<Integer, Object> response;

	public Library() {
		for (int i = 0; i < N; i++) {
			Thread td = new Thread(new LibraryThread(PORT + i, this), Integer.toString(PORT + i));
			td.start();
			threadArray.add(td);
		}

	}

	public void init(char[] password, String alias, KeyStore ks) {
		response = new ConcurrentHashMap<Integer, Object>();
		requestID++;
		System.out.println("init: " + requestID);
		request.put(requestID, new Object[] { requestID, "init", password, alias, ks });
		while(response.size() < N/2);
		System.out.println("Init done!");
	}

	public void register_user() {
		response = new ConcurrentHashMap<Integer, Object>();
		requestID++;
		System.out.println("register_user: " + requestID);
		request.put(requestID, new Object[] { requestID, "register_user" });
		while(response.size() < N/2);
	}

	public void save_password(byte[] domain, byte[] username, byte[] password) {
		response = new ConcurrentHashMap<Integer, Object>();
		requestID++;
		request.put(requestID, new Object[] { requestID, "save_password", domain, username, password });
		while(response.size() < N/2);
	}

	public byte[] retrieve_password(byte[] domain, byte[] username) {
		response = new ConcurrentHashMap<Integer, Object>();
		requestID++;
		request.put(requestID, new Object[] { requestID, "retrieve_password", domain, username });
		while(response.size() < N);
		return (byte[])response.get(10000);
	}

	public void close() {
		end = true;
	}

	public Object[] getRequest(int id) {
		return request.get(id);
	}
	
	public int getRequestSize() {
		return request.size();
	}

	public ConcurrentHashMap<Integer, Object> getResponse() {
		return response;
	}

	public void addResponse(Integer port, Object value) {
		response.put(port, value);
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

	public boolean isEnd() {
		return end;
	}

}
