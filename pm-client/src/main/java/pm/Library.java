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
import java.util.Arrays;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

import pm.exception.InconcistencyException;

public class Library {

	protected static final int F = 1;

	protected static int N_SERVERS = F * 3 + 1;

	protected static int MAJORITY = (int) Math.round((double) (N_SERVERS + F) / 2);

	protected static final int PORT = 10000;

	private ArrayList<Thread> threadArray = new ArrayList<Thread>(N_SERVERS);

	private int requestID = 0;

	private ConcurrentHashMap<Integer, Object[]> request = new ConcurrentHashMap<Integer, Object[]>();
	private ConcurrentHashMap<Integer, Object> response;

	private boolean end = false;

	public Library() {
		// Starts N_SERVERS Threads
		for (int i = 0; i < N_SERVERS; i++) {
			Thread td = new Thread(new LibraryThread(PORT + i, this), Integer.toString(PORT + i));
			td.start();
			threadArray.add(td);
		}
		System.out.println("Majority is " + MAJORITY);
	}

	public void init(char[] password, String alias, KeyStore ks) {
		response = new ConcurrentHashMap<Integer, Object>();
		requestID++;
		System.out.println("init: " + requestID);
		request.put(requestID, new Object[] { requestID, "init", password, alias, ks });
		while (response.size() < MAJORITY)
			;
	}

	public void register_user() {
		response = new ConcurrentHashMap<Integer, Object>();
		requestID++;
		System.out.println("register_user: " + requestID);
		request.put(requestID, new Object[] { requestID, "register_user" });
		while (response.size() < MAJORITY)
			;
	}

	public void save_password(byte[] domain, byte[] username, byte[] password) {

		System.out.println("save_password: " + requestID);

		// Read Operation
		response = new ConcurrentHashMap<Integer, Object>();
		requestID++;
		request.put(requestID, new Object[] { requestID, "retrieve_password", domain, username });
		while (response.size() < MAJORITY)
			;

		int total = 0;
		BigInteger max_ts = BigInteger.ZERO;

		// Verifies the responses from the server
		HashMap<Object, Integer> majority = new HashMap<Object, Integer>();
		for (Object values : response.values()) {
			BigInteger ts = new BigInteger(((byte[][]) values)[1]);
			// If the timestamp does not exists initialize it
			if (majority.get(ts) == null) {
				majority.put(ts, 1);
			} else {
				majority.put(ts, majority.get(ts) + 1);
			}
			if (majority.get(ts) > total) {
				total = majority.get(ts);
				max_ts = ts;

			} else if (majority.get(ts) == total && max_ts.compareTo(ts) < 0) {
				// if the timestamp found is the total and the max_ts is not
				// equal, the max_ts is the ts
				total = majority.get(ts);
				max_ts = ts;
			}
		}

		if (total < MAJORITY) {
			throw new InconcistencyException();
		}

		// Get all the values of the max_ts
		ArrayList<byte[]> pwList = new ArrayList<byte[]>();
		for (Object values : response.values()) {
			BigInteger ts = new BigInteger(((byte[][]) values)[1]);
			if (ts.compareTo(max_ts) == 0) {
				pwList.add(((byte[][]) values)[0]);
			}
		}
		// Verifies if all the values received is not equal
		for (int i = 1; i < pwList.size(); i++) {
			if (!Arrays.equals(pwList.get(0), pwList.get(i))) {
				throw new InconcistencyException();
			}
		}

		// Write Operation
		response = new ConcurrentHashMap<Integer, Object>();
		requestID++;
		BigInteger ts = max_ts.add(BigInteger.ONE);
		request.put(requestID,
				new Object[] { requestID, "save_password", domain, username, password, ts.toByteArray() });
		while (response.size() < MAJORITY)
			;
	}

	public byte[] retrieve_password(byte[] domain, byte[] username) {

		System.out.println("retrieve_password: " + requestID);

		// Read Operation
		response = new ConcurrentHashMap<Integer, Object>();
		requestID++;
		request.put(requestID, new Object[] { requestID, "retrieve_password", domain, username });
		while (response.size() < MAJORITY)
			;

		byte[][] pw_ts = null;
		int total = 0;
		BigInteger max_ts = BigInteger.ZERO;

		HashMap<Object, Integer> majority = new HashMap<Object, Integer>();
		for (Object values : response.values()) {
			BigInteger ts = new BigInteger(((byte[][]) values)[1]);
			if (majority.get(ts) == null) {
				majority.put(ts, 1);
			} else {
				majority.put(ts, majority.get(ts) + 1);
			}
			// if the ts is bigger than the total, update the value of max_ts
			// and save the values returned by the server
			if (majority.get(ts) > total) {
				total = majority.get(ts);
				max_ts = ts;
				pw_ts = (byte[][]) values;
			} else if (majority.get(ts) == total && max_ts.compareTo(ts) < 0) {
				total = majority.get(ts);
				max_ts = ts;
				pw_ts = (byte[][]) values;
			}
		}

		if (total < MAJORITY) {
			throw new InconcistencyException();
		}

		ArrayList<byte[]> pwList = new ArrayList<byte[]>();
		for (Object values : response.values()) {
			BigInteger ts = new BigInteger(((byte[][]) values)[1]);
			if (ts.compareTo(max_ts) == 0) {
				pwList.add(((byte[][]) values)[0]);
			}
		}
		for (int i = 1; i < pwList.size(); i++) {
			if (!Arrays.equals(pwList.get(0), pwList.get(i))) {
				throw new InconcistencyException();
			}
		}

		// Write Operation
		// pw_ts[0] - password
		// pw_ts[1] - timestamp
		// pw_ts[2] - write_rank
		response = new ConcurrentHashMap<Integer, Object>();
		requestID++;
		request.put(requestID,
				new Object[] { requestID, "save_password", domain, username, pw_ts[0], pw_ts[1], pw_ts[2] });
		while (response.size() < MAJORITY)
			;

		return pw_ts[0];
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
