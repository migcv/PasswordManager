package pm;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.rmi.*;
import java.rmi.server.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import pm.exception.*;

public class Server extends UnicastRemoteObject implements ServerService, Serializable {

	private static final long serialVersionUID = 1L;
	
	private int port;

	private PublicKey publicKey;
	private PrivateKey privateKey;

	private Map<Key, ArrayList<Triplet>> publicKeyMap = new HashMap<Key, ArrayList<Triplet>>();

	private Map<BigInteger, Session> sessionKeyMap = new HashMap<BigInteger, Session>();

	private Map<Key, BigInteger> timestampMap = new HashMap<Key, BigInteger>();

	Utils utl = new Utils();

	protected Server(int port) throws RemoteException {
		super();
		
		this.port = port;
		
		// Generate a key pair, public & private key
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");

			keyGen.initialize(2048);
			KeyPair keypair = keyGen.genKeyPair();

			privateKey = keypair.getPrivate();
			publicKey = keypair.getPublic();

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	public ArrayList<byte[]> init(Key publicKey, byte[] sig) throws RemoteException {
		
		System.out.println(this.port + " > Received Request <Init>");

		// Verify Signature
		if (!utl.verifySignature(publicKey, sig, publicKey.getEncoded())) {
			System.out.println(port + " > Signature NOT valid!");
			throw new SignatureWrongException();
		}

		BigInteger id = utl.generateBigInteger();
		BigInteger nounce = utl.generateBigInteger();

		SecretKey sessionKey = utl.createSessionKey();
		Session ss = new Session(publicKey, sessionKey, nounce);
		sessionKeyMap.put(id, ss);
		Cipher cipher;
		byte[] sessionKeyCiphered = null, signature = null, nounceCiphered = null, timestampCiphered = null, iv = null,
				idCiphered = null;
		ArrayList<byte[]> res = new ArrayList<byte[]>();

		try {
			// Cipher Session Key with Client's public key
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			sessionKeyCiphered = cipher.doFinal(sessionKey.getEncoded());

			// Generate a random IV
			SecureRandom random = new SecureRandom();
			iv = new byte[16];
			random.nextBytes(iv);
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			// Sends the most recent timestamp
			BigInteger timestamp;
			if(timestampMap == null) {
				timestampMap = new HashMap<Key, BigInteger>();
			}
			if (timestampMap.get(publicKey) == null) {
				timestamp = BigInteger.ZERO;
				timestampMap.put(publicKey, timestamp);
			} else {
				timestamp = timestampMap.get(publicKey);
			}
			byte[] timestampBytes = timestamp.toByteArray();

			// Cipher the nounce and the id with the Session Key
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, ss.getSessionKey(), ivspec);
			nounceCiphered = cipher.doFinal(nounce.toByteArray());
			timestampCiphered = cipher.doFinal(timestampBytes);
			idCiphered = cipher.doFinal(id.toByteArray());

			// Signature contaning [ Public Key, Session Key, Nonce, id, IV ]
			// signed with Server's private key
			signature = sign(this.publicKey.getEncoded(), sessionKeyCiphered, idCiphered, timestampCiphered,
					nounceCiphered, iv);

			// Create the array to send to the client
			res.add(this.publicKey.getEncoded());
			res.add(sessionKeyCiphered);
			res.add(idCiphered);
			res.add(timestampCiphered);
			res.add(nounceCiphered);
			res.add(iv);
			res.add(signature);

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}

		return res;
	}

	public void register(Key publicKey, byte[] id, byte[] nonce, byte[] iv, byte[] signature) throws RemoteException {

		System.out.println(port + " > Received Request <Register>");
		
		// Verify Signature
		if (!utl.verifySignature(publicKey, signature, publicKey.getEncoded(), id, nonce, iv)) {
			System.out.println(port + " > Signature NOT valid!");
			throw new SignatureWrongException();
		}

		IvParameterSpec ivspec = new IvParameterSpec(iv);

		byte[] nounceDecipher = null, idDecipher = null;
		try {

			// Decipher ID with Server's private key
			Cipher decipherID = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			decipherID.init(Cipher.DECRYPT_MODE, this.privateKey);
			idDecipher = decipherID.doFinal(id);

			BigInteger userID = new BigInteger(idDecipher);

			Session ss = sessionKeyMap.get(userID);

			// Decipher Nounce with Session key
			Cipher decipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			decipher.init(Cipher.DECRYPT_MODE, ss.getSessionKey(), ivspec);
			nounceDecipher = decipher.doFinal(nonce);

			BigInteger bg = new BigInteger(nounceDecipher);

			if (!bg.equals(ss.getNounce().shiftLeft(2))) {
				System.out.println(port + " > Nonce NOT valid!");
				throw new InvalidNounceException();
			}

			ss.setNounce(bg);

			publicKeyMap.put(publicKey, new ArrayList<Triplet>());

			Thread.sleep(5000);

		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public void put(Key publicKey, byte[] id, byte[] domain, byte[] username, byte[] password, byte[] timestamp,
			byte[] valueSignature, byte[] iv, byte[] n, byte[] signature)
			throws RemoteException, PublicKeyDoesntExistException, SignatureWrongException {
		
		System.out.println(port + " > Received Resquest <Put>");

		// Verify Signature
		if (!utl.verifySignature(publicKey, signature, id, domain, username, password, iv)) {
			System.out.println(port + " > Signature NOT valid!");
			throw new SignatureWrongException();
		}

		byte[] domainDeciphered = null, usernameDeciphered = null, passwordDeciphered = null, nounceDeciphered = null,
				idDeciphered = null, timestampDeciphered = null;

		// Decipher content
		try {

			// Decipher ID with Server's private key
			Cipher decipherID = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			decipherID.init(Cipher.DECRYPT_MODE, this.privateKey);
			idDeciphered = decipherID.doFinal(id);

			BigInteger userID = new BigInteger(idDeciphered);

			Session ss = sessionKeyMap.get(userID);

			// Decipher Nounce with Session key
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			Cipher decipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			decipher.init(Cipher.DECRYPT_MODE, ss.getSessionKey(), ivspec);
			domainDeciphered = decipher.doFinal(domain);
			usernameDeciphered = decipher.doFinal(username);
			passwordDeciphered = decipher.doFinal(password);
			nounceDeciphered = decipher.doFinal(n);
			timestampDeciphered = decipher.doFinal(timestamp);

			BigInteger bg = new BigInteger(nounceDeciphered);

			if (!bg.equals(ss.getNounce().shiftLeft(2))) {
				System.out.println(port + " > Nonce NOT valid!");
				throw new InvalidNounceException();
			}

			ss.setNounce(bg);

		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}

		boolean exists = false;
		ArrayList<Triplet> tripletList = publicKeyMap.get(publicKey);

		// Verifies if the publicKey exists
		if (tripletList == null) {
			System.out.println(port + " > Public Key does't exists!");
			throw new PublicKeyDoesntExistException();
		}
		
		BigInteger wtimestamp = new BigInteger(timestampDeciphered); 
		
		if(wtimestamp.compareTo(timestampMap.get(publicKey)) <= 0) {
			System.out.println(port + " > Timestamp NOT valid!");
			throw new InvalidTimestampException();
		}

		for (int i = 0; i < tripletList.size(); i++) {
			// Verifies if the domain & username exists, if true, replace
			// password with new one
			if (Arrays.equals(tripletList.get(i).getDomain(),
					utl.diggestSalt(domainDeciphered, tripletList.get(i).getSalt()))
					&& Arrays.equals(tripletList.get(i).getUsername(),
							utl.diggestSalt(usernameDeciphered, tripletList.get(i).getSalt()))) {

				SecureRandom random = new SecureRandom();
				byte[] salt = new byte[64];
				random.nextBytes(salt);

				tripletList.get(i).setDomain(utl.diggestSalt(domainDeciphered, salt));
				tripletList.get(i).setUsername(utl.diggestSalt(usernameDeciphered, salt));
				tripletList.get(i).setSalt(salt);
				tripletList.get(i).setValueSignature(valueSignature);
				tripletList.get(i).setTimestamp(timestampDeciphered);
				tripletList.get(i).setPassword(passwordDeciphered);
				
				timestampMap.put(publicKey, wtimestamp);
				
				exists = true;
				break;
			}
		}
		// If domain & username doesnt exists, add new triplet (doamin,
		// username, password)
		if (!exists) {
			SecureRandom random = new SecureRandom();
			byte[] salt = new byte[64];
			random.nextBytes(salt);

			domainDeciphered = utl.diggestSalt(domainDeciphered, salt);
			usernameDeciphered = utl.diggestSalt(usernameDeciphered, salt);

			tripletList.add(new Triplet(domainDeciphered, usernameDeciphered, passwordDeciphered, salt, timestampDeciphered,
					valueSignature, signature));
			
			timestampMap.put(publicKey, wtimestamp);
		}
		// Put back the list of triplet in the map
		publicKeyMap.put(publicKey, tripletList);

		saveState();
	}

	public ArrayList<byte[]> get(Key publicKey, byte[] user_id, byte[] read_id, byte[] domain, byte[] username, byte[] iv, byte[] n,
			byte[] signature) throws RemoteException, PublicKeyDoesntExistException,
			DomainOrUsernameDoesntExistException, SignatureWrongException {
		
		System.out.println(port + " > Request Received <Get>");
		
		// Verify Signature
		if (!utl.verifySignature(publicKey, signature, publicKey.getEncoded(), user_id, read_id, domain, username, n, iv)) {
			System.out.println(port + " > Signature NOT valid!");
			throw new SignatureWrongException();
		}

		byte[] domainDeciphered = null, usernameDeciphered = null, signatureToSend = null, nounceDeciphered = null,
				idDeciphered = null, readIDDeciphered = null, timestampCiphered = null, readIDCiphered = null;

		// Decipher content
		try {
			// Decipher ID with Server's private key
			Cipher decipherID = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			decipherID.init(Cipher.DECRYPT_MODE, this.privateKey);
			idDeciphered = decipherID.doFinal(user_id);

			BigInteger userID = new BigInteger(idDeciphered);

			Session ss = sessionKeyMap.get(userID);

			// Decipher Nounce with Session key
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			Cipher decipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			decipher.init(Cipher.DECRYPT_MODE, ss.getSessionKey(), ivspec);

			domainDeciphered = decipher.doFinal(domain);
			usernameDeciphered = decipher.doFinal(username);
			nounceDeciphered = decipher.doFinal(n);
			readIDDeciphered = decipher.doFinal(read_id);

			BigInteger bg = new BigInteger(nounceDeciphered);

			if (!bg.equals(ss.getNounce().shiftLeft(2))) {
				System.out.println(port + " > Nonce NOT valid!");
				throw new InvalidNounceException();
			}

			ss.setNounce(bg.shiftLeft(2));

			byte[] passwordCiphered = null;
			byte[] nounceCiphered = null;
			ArrayList<Triplet> tripletList = publicKeyMap.get(publicKey);

			// Verifies if the publicKey exists
			if (tripletList == null) {
				System.out.println(port + " > Public Key doesn't exists!");
				throw new PublicKeyDoesntExistException();
			}
			
			for (int i = 0; i < tripletList.size(); i++) {
				// Verifies if the domain & username exists, if true, sends
				// password
				if (Arrays.equals(tripletList.get(i).getDomain(),
						utl.diggestSalt(domainDeciphered, tripletList.get(i).getSalt()))
						&& Arrays.equals(tripletList.get(i).getUsername(),
								utl.diggestSalt(usernameDeciphered, tripletList.get(i).getSalt()))) {

					// Generate a random IV
					SecureRandom random = new SecureRandom();
					byte[] res_iv = new byte[16];
					random.nextBytes(iv);
					ivspec = new IvParameterSpec(res_iv);

					// Cipher password with session key

					// COM CBC
					// Cipher cipher =
					// Cipher.getInstance("AES/CBC/PKCS5Padding");
					// cipher.init(Cipher.ENCRYPT_MODE,
					// sessionKeyMap.get(publicKey), ivspec);

					// COM ECB
					Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
					cipher.init(Cipher.ENCRYPT_MODE, ss.getSessionKey());

					passwordCiphered = cipher.doFinal(tripletList.get(i).getPassword());
					nounceCiphered = cipher.doFinal(ss.getNounce().toByteArray());
					readIDCiphered = cipher.doFinal(readIDDeciphered);
					
					timestampCiphered = cipher.doFinal(tripletList.get(i).getTimestamp());
					
					byte[] valueSignature = tripletList.get(i).getValueSignature();

					tripletList.get(i).addSignturesArray(signature);

					// Signature contaning [ password, nonce, iv ] signed with
					// Server's private key
					signatureToSend = sign(passwordCiphered, timestampCiphered, valueSignature, readIDCiphered, nounceCiphered, iv);

					// Create List to send with [ password_ciphered,
					// iv,signature,nounce ]
					ArrayList<byte[]> res = new ArrayList<byte[]>();
					res.add(passwordCiphered);
					res.add(timestampCiphered);
					res.add(valueSignature);
					res.add(readIDCiphered);
					res.add(nounceCiphered);
					res.add(iv);
					res.add(signatureToSend);
					return res;
				}
			}
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		System.out.println(port + " > Domain and/or Username doesn't exists!");
		throw new DomainOrUsernameDoesntExistException();
	}

	// Function that signs data with Server's private key
	public byte[] sign(byte[]... arrays) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		byte[] toSend = utl.concat(arrays);

		Signature rsaForSign = Signature.getInstance("SHA256withRSA");
		rsaForSign.initSign(this.privateKey);
		rsaForSign.update(toSend);
		byte[] signature = rsaForSign.sign();
		return signature;
	}

	// Saves the state of the server in file pmserver.ser
	public synchronized void saveState() {
		try {
			FileOutputStream fileOut = new FileOutputStream("pmserver" + port + ".ser");
			ObjectOutputStream out = new ObjectOutputStream(fileOut);
			out.writeObject(this);
			out.close();
			fileOut.close();
		} catch (IOException i) {
			i.printStackTrace();
		}
	}

}
