package pm;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.rmi.*;
import java.rmi.server.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.KeyGenerator;

import pm.exception.DomainOrUsernameDoesntExistException;
import pm.exception.PublicKeyDoesntExistException;
import pm.exception.SignatureWrongException;

public class Server extends UnicastRemoteObject implements ServerService, Serializable {

	private static final long serialVersionUID = 1L;

	private Map<Key, ArrayList<Triplet>> publicKeyMap = new HashMap<Key, ArrayList<Triplet>>();

	protected Server() throws RemoteException {
		super();
	}

	public void register(Key publicKey) throws RemoteException {

		publicKeyMap.put(publicKey, new ArrayList<Triplet>());

	}

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password, byte[] signature)
			throws RemoteException, PublicKeyDoesntExistException, SignatureWrongException {
		// Verify Signature
		if (!verifySignatue(publicKey, signature, domain, username, password)) {
			throw new SignatureWrongException();
		}

		boolean exists = false;
		ArrayList<Triplet> tripletList = publicKeyMap.get(publicKey);

		// Verifies if the publicKey exists
		if (tripletList == null) {
			throw new PublicKeyDoesntExistException();
		}

		for (int i = 0; i < tripletList.size(); i++) {
			// Verifies if the domain & username exists, if true, replace
			// password with new one
			if (Arrays.equals(tripletList.get(i).getDomain(), domain)
					&& Arrays.equals(tripletList.get(i).getUsername(), username)) {
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
		saveState();
	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username, byte[] signature) throws RemoteException,
			PublicKeyDoesntExistException, DomainOrUsernameDoesntExistException, SignatureWrongException {
		// Verify Signature
		if (!verifySignatue(publicKey, signature, domain, username)) {
			throw new SignatureWrongException();
		}
		
		ArrayList<Triplet> tripletList = publicKeyMap.get(publicKey);

		// Verifies if the publicKey exists
		if (tripletList == null) {
			throw new PublicKeyDoesntExistException();
		}

		for (int i = 0; i < tripletList.size(); i++) {
			// Verifies if the domain & username exists, if true, sends password
			if (Arrays.equals(tripletList.get(i).getDomain(), domain)
					&& Arrays.equals(tripletList.get(i).getUsername(), username)) {
				return tripletList.get(i).getPassword();
			}
		}

		throw new DomainOrUsernameDoesntExistException();
	}

	// Generate a session key (NOT USED YET)
	@SuppressWarnings("unused")
	private Key sessionKey() {
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

	// Checks if the signature is valid
	private boolean verifySignatue(Key publicKey, byte[] signature, byte[]... data) {
		byte[] allData = concat(data);
		boolean res = false;
		try {
			Signature rsaForVerify = Signature.getInstance("SHA256withRSA");
			rsaForVerify.initVerify((PublicKey) publicKey);
			rsaForVerify.update(allData);
			res = rsaForVerify.verify(signature);
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return res;
	}

	// Auxiliary function for verifySignature, to join all data received from the client
	private byte[] concat(byte[]... arrays) {
		// Determine the length of the result array
		int totalLength = 0;
		for (int i = 0; i < arrays.length; i++) {
			totalLength += arrays[i].length;
		}
		// create the result array
		byte[] result = new byte[totalLength];
		// copy the source arrays into the result array
		int currentIndex = 0;
		for (int i = 0; i < arrays.length; i++) {
			System.arraycopy(arrays[i], 0, result, currentIndex, arrays[i].length);
			currentIndex += arrays[i].length;
		}
		return result;
	}

	// Saves the state of the server in file pmserver.ser
	private void saveState() {
		try {
			FileOutputStream fileOut = new FileOutputStream("pmserver.ser");
			ObjectOutputStream out = new ObjectOutputStream(fileOut);
			out.writeObject(this);
			out.close();
			fileOut.close();
			System.out.println("Serialized data is saved in pmserver.ser");
		} catch (IOException i) {
			i.printStackTrace();
		}
	}
}
