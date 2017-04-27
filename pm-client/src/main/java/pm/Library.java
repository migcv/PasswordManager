package pm;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

public class Library {

	protected static final int F = 2;
	
	protected static int N_SERVERS;
	
	protected static final int PORT = 10000;

	private ArrayList<Thread> threadArray = new ArrayList<Thread>(N_SERVERS);
	private int requestID = 0;
	private ConcurrentHashMap<Integer, Object[]> request = new ConcurrentHashMap<Integer, Object[]>();
	private boolean end = false;

	private ConcurrentHashMap<Integer, Object> response;

	private BigInteger timestamp;

	public Library() {
		N_SERVERS = F * 3 + 1;
		
		for (int i = 0; i < N_SERVERS; i++) {
			Thread td = new Thread(new LibraryThread(PORT + i, this), Integer.toString(PORT + i));
			td.start();
			threadArray.add(td);
		}

	}

	public void init(char[] password, String alias, KeyStore ks) {
		Object res = null;
		Integer total = 0;
		response = new ConcurrentHashMap<Integer, Object>();
		requestID++;
		System.out.println("init: " + requestID);
		request.put(requestID, new Object[] { requestID, "init", password, alias, ks });
		while(response.size() < (N_SERVERS + F) / 2);
		HashMap<Object, Integer> majority = new HashMap<Object, Integer>();
		for (Object values : response.values()) {
			if (majority.get(values) == null) {
				majority.put(values, 1);
			} else {
				majority.put(values, majority.get(values) + 1);
			}
			if (majority.get(values) > total) {
				total = majority.get(values);
				res = values;
			}
		}
		timestamp = (BigInteger) res;
		System.out.println("Init done! Timestamp: " + timestamp);
	}

	public void register_user() {
		response = new ConcurrentHashMap<Integer, Object>();
		requestID++;
		System.out.println("register_user: " + requestID);
		request.put(requestID, new Object[] { requestID, "register_user" });
		while (response.size() < (N_SERVERS + F) / 2)
			;
	}

	public void save_password(byte[] domain, byte[] username, byte[] password) {
		response = new ConcurrentHashMap<Integer, Object>();
		requestID++;
		timestamp = timestamp.add(BigInteger.ONE);
		request.put(requestID, new Object[] { requestID, "save_password", domain, username, password, timestamp.toByteArray() });
		while (response.size() < (N_SERVERS + F) / 2)
			;
	}

	public byte[] retrieve_password(byte[] domain, byte[] username) {
		Object res = null;
		Integer total = 0;
		response = new ConcurrentHashMap<Integer, Object>();
		requestID++;
		request.put(requestID, new Object[] { requestID, "retrieve_password", domain, username });
		while (response.size() < (N_SERVERS + F) / 2);
		HashMap<Object, Integer> majority = new HashMap<Object, Integer>();
		for (Object values : response.values()) {
			if (majority.get(values) == null) {
				majority.put(values, 1);
			} else {
				majority.put(values, majority.get(values) + 1);
			}
			if (majority.get(values) > total) {
				total = majority.get(values);
				res = values;
			}
		}
		return (byte[]) res;
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

	public void addResponse(Integer port, Integer id, Object value) {
		if (requestID == id) {
			response.put(port, value);
		}
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
			System.out.println("KeyStoreNotFound");
			return null;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return ks;
	}

	public boolean isEnd() {
		return end;
	}

}
