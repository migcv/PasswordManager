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
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import pm.exception.DomainOrUsernameDoesntExistException;
import pm.exception.InvalidNounceException;
import pm.exception.PublicKeyDoesntExistException;
import pm.exception.SignatureWrongException;

public class Server extends UnicastRemoteObject implements ServerService, Serializable {

	private static final long serialVersionUID = 1L;

	private PublicKey publicKey;
	private PrivateKey privateKey;
	private BigInteger nounce = null;

	private Map<Key, ArrayList<Triplet>> publicKeyMap = new HashMap<Key, ArrayList<Triplet>>(); 

	private Map<Key, SecretKey> sessionKeyMap = new HashMap<Key, SecretKey>();

	Utils utl = new Utils();

	protected Server() throws RemoteException {
		super();
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

		// Verify Signature
		if (!utl.verifySignature(publicKey, sig, publicKey.getEncoded())) {
			throw new SignatureWrongException();
		}

		SecretKey sessionKey = utl.createSessionKey();
		sessionKeyMap.put(publicKey, sessionKey);
		Cipher cipher;
		byte[] sessionKeyCiphered = null, signature = null, nounceCiphered = null, iv = null;

		Random rand = new SecureRandom();
		this.nounce = new BigInteger(30000, rand);

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

			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, sessionKeyMap.get(publicKey), ivspec);
			nounceCiphered = cipher.doFinal(nounce.toByteArray());

			// Signature contaning [ Public Key, Session Key, Nonce, IV ] signed
			// with Server's private
			// key
			signature = sign(this.publicKey.getEncoded(), sessionKeyCiphered, nounceCiphered, iv);

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
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		ArrayList<byte[]> res = new ArrayList<byte[]>();
		res.add(this.publicKey.getEncoded());
		res.add(sessionKeyCiphered);
		res.add(nounceCiphered);
		res.add(iv);
		res.add(signature);
		return res;
	}

	public void register(Key publicKey, byte[] nonce, byte[] iv, byte[] signature) throws RemoteException {

		// Verify Signature
		if (!utl.verifySignature(publicKey, signature, publicKey.getEncoded(), nonce, iv)) {
			throw new SignatureWrongException();
		}

		IvParameterSpec ivspec = new IvParameterSpec(iv);

		byte[] nounceDecipher;
		try {
			Cipher decipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			decipher.init(Cipher.DECRYPT_MODE, sessionKeyMap.get(publicKey), ivspec);
			nounceDecipher = decipher.doFinal(nonce);

			BigInteger bg = new BigInteger(nounceDecipher);

			nounce = nounce.shiftLeft(2);

			if (!bg.equals(nounce)) {
				throw new InvalidNounceException();
			}

			publicKeyMap.put(publicKey, new ArrayList<Triplet>());

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
		}

	}

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password, byte[] iv, byte[] n,
			byte[] signature) throws RemoteException, PublicKeyDoesntExistException, SignatureWrongException {

		// Verify Signature
		if (!utl.verifySignature(publicKey, signature, domain, username, password, iv)) {
			throw new SignatureWrongException();
		}

		byte[] domainDeciphered = null, usernameDeciphered = null, passwordDeciphered = null, nounceDeciphered = null;

		// Decipher content
		try {
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, sessionKeyMap.get(publicKey), ivspec);
			domainDeciphered = cipher.doFinal(domain);
			usernameDeciphered = cipher.doFinal(username);
			passwordDeciphered = cipher.doFinal(password);
			nounceDeciphered = cipher.doFinal(n);
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

		BigInteger bg = new BigInteger(nounceDeciphered);

		nounce = nounce.shiftLeft(2);

		if (!bg.equals(nounce)) {
			throw new InvalidNounceException();
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

				tripletList.get(i).setPassword(passwordDeciphered);

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

			tripletList.add(new Triplet(domainDeciphered, usernameDeciphered, passwordDeciphered, salt));
		}
		// Put back the list of triplet in the map
		publicKeyMap.put(publicKey, tripletList);

		saveState();
	}

	public ArrayList<byte[]> get(Key publicKey, byte[] domain, byte[] username, byte[] iv, byte[] n, byte[] signature)
			throws RemoteException, PublicKeyDoesntExistException, DomainOrUsernameDoesntExistException,
			SignatureWrongException {
		// Verify Signature
		if (!utl.verifySignature(publicKey, signature, publicKey.getEncoded(), domain, username, n, iv)) {
			throw new SignatureWrongException();
		}

		byte[] domainDeciphered = null, usernameDeciphered = null, signatureToSend = null, nounceDeciphered = null;

		// Decipher content
		try {
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, sessionKeyMap.get(publicKey), ivspec);
			domainDeciphered = cipher.doFinal(domain);
			usernameDeciphered = cipher.doFinal(username);
			nounceDeciphered = cipher.doFinal(n);

			BigInteger bg = new BigInteger(nounceDeciphered);

			nounce = nounce.shiftLeft(2);

			if (!bg.equals(nounce)) {
				throw new InvalidNounceException();
			}

			nounce = nounce.shiftLeft(2);

			byte[] passwordCiphered = null;
			byte[] nounceCiphered = null;
			ArrayList<Triplet> tripletList = publicKeyMap.get(publicKey);

			// Verifies if the publicKey exists
			if (tripletList == null) {
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
					cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
					cipher.init(Cipher.ENCRYPT_MODE, sessionKeyMap.get(publicKey));

					// System.out.println(new
					// String(tripletList.get(i).getPassword()));

					passwordCiphered = cipher.doFinal(tripletList.get(i).getPassword());
					nounceCiphered = cipher.doFinal(nounce.toByteArray());

					// Signature contaning [ password, nonce, iv ] signed with
					// Server's private key
					signatureToSend = sign(passwordCiphered, nounceCiphered, iv);

					// Create List to send with [ password_ciphered, iv,
					// signature,
					// nounce ]
					ArrayList<byte[]> res = new ArrayList<byte[]>();
					res.add(passwordCiphered);
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

		throw new DomainOrUsernameDoesntExistException();
	}

	// Funtion that signs data with Server's private key
	public byte[] sign(byte[]... arrays) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		byte[] toSend = utl.concat(arrays);

		Signature rsaForSign = Signature.getInstance("SHA256withRSA");
		rsaForSign.initSign(this.privateKey);
		rsaForSign.update(toSend);
		byte[] signature = rsaForSign.sign();
		return signature;
	}

	// Saves the state of the server in file pmserver.ser
	public void saveState() {
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
