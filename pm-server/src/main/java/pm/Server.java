package pm;

import java.io.UnsupportedEncodingException;
import java.rmi.*;
import java.rmi.server.*;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.KeyGenerator;

import pm.exception.DomainOrUsernameDoesntExistException;
import pm.exception.PublicKeyDoesntExistException;

public class Server extends UnicastRemoteObject implements ServerService {

	private static final long serialVersionUID = 1L;

	private Map<Key, ArrayList<Triplet>> publicKeyMap = new HashMap<Key, ArrayList<Triplet>>();

	protected Server() throws RemoteException {
		super();
	}

	public void register(Key publicKey) throws RemoteException {

		publicKeyMap.put(publicKey, new ArrayList<Triplet>());

	}

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password)
			throws RemoteException, PublicKeyDoesntExistException {
		boolean exists = false;
		ArrayList<Triplet> tripletList = publicKeyMap.get(publicKey);

		// Verifies if the publicKey exists
		if (tripletList == null) {
			throw new PublicKeyDoesntExistException();
		}

		for (int i = 0; i < tripletList.size(); i++) {
			// Verifies if the domain & username exists, if true, replace
			// password with new one
			if (tripletList.get(i).getDomain().equals(domain) && tripletList.get(i).getUsername().equals(username)) {
				tripletList.get(i).setPassword(password);
				exists = true;
				break;
			}
		}
		// If domain & username doesnt exists, add new triplet (doamin,
		// username, password)
		if (!exists) {
			tripletList.add(new Triplet(domain, username, password));
		}
		// Put back the list of triplet in the map
		publicKeyMap.put(publicKey, tripletList);
		try {
			System.out.println(new String(publicKeyMap.get(publicKey).get(0).getDomain(), "UTF-8"));
			System.out.println(new String(publicKeyMap.get(publicKey).get(0).getUsername(), "UTF-8"));
			System.out.println(new String(publicKeyMap.get(publicKey).get(0).getPassword(), "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username)
			throws RemoteException, PublicKeyDoesntExistException, DomainOrUsernameDoesntExistException {
		ArrayList<Triplet> tripletList = publicKeyMap.get(publicKey);

		// Verifies if the publicKey exists
		if (tripletList == null) {
			throw new PublicKeyDoesntExistException();
		}

		for (int i = 0; i < tripletList.size(); i++) {
			// Verifies if the domain & username exists, if true, sends password
			try {
				System.out.println(new String(tripletList.get(i).getDomain(), "UTF-8"));
				System.out.println(new String(tripletList.get(i).getUsername(), "UTF-8"));
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
			if (Arrays.equals(tripletList.get(i).getDomain(), domain)
					&& Arrays.equals(tripletList.get(i).getUsername(), username)) {
				return tripletList.get(i).getPassword();
			}
		}

		throw new DomainOrUsernameDoesntExistException();
	}

	public Key sessionKey() {
		KeyGenerator keyGenerator;
		Key key = null;
		try {
			keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(256, new SecureRandom());
			key = keyGenerator.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return key;

	}

}
