package pm;

import java.io.Serializable;
import java.math.BigInteger;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import pm.exception.DomainOrUsernameDoesntExistException;
import pm.exception.InconcistencyException;
import pm.exception.InvalidNounceException;
import pm.exception.InvalidTimestampException;
import pm.exception.SignatureWrongException;

public class LibraryThread implements Serializable, Runnable {

	private static final long serialVersionUID = 1L;

	private ServerService server = null;

	private KeyManagement ck = null;

	private PublicKey serverKey = null;
	private SecretKey sessionKey = null;

	private BigInteger userID = null;

	private BigInteger nounce = null;

	private BigInteger readID = BigInteger.ZERO;

	private int port;
	private Library lb;

	private int requestID = 0;

	public LibraryThread(int port, Library lb) {
		this.port = port;
		this.lb = lb;
	}

	public void run() {
		while (true) {
			while (lb.getRequestSize() <= requestID) {
				try {
					Thread.sleep(250);
				} catch (InterruptedException e) {
				}
			}
			Object[] request = lb.getRequest(requestID + 1);
			System.out.println(port + " REQUEST: " + request[0] + " " + request[1]);
			if (request[1].equals("init")) {
				init((char[]) request[2], (String) request[3], (KeyStore) request[4]);
				requestID = ((Integer) request[0]).intValue();
				lb.addResponse(port, requestID, true);
			} 
			else if (request[1].equals("register_user")) {
				register_user();
				requestID = ((Integer) request[0]).intValue();
				lb.addResponse(port, requestID, true);
			} 
			else if (request[1].equals("save_password")) {
				if (request.length < 7) { // Default Write Ranke (UserID)
					save_password((byte[]) request[2], (byte[]) request[3], (byte[]) request[4], (byte[]) request[5]);
				} else { // Use Write Rank received
					save_password((byte[]) request[2], (byte[]) request[3], (byte[]) request[4], (byte[]) request[5],
							(byte[]) request[6]);
				}
				requestID = ((Integer) request[0]).intValue();
				lb.addResponse(port, requestID, true);
			} 
			else if (request[1].equals("retrieve_password")) {
				byte[][] res = retrieve_password((byte[]) request[2], (byte[]) request[3]);
				requestID = ((Integer) request[0]).intValue();
				if(res == null) {
					res = new byte[][]{ "".getBytes(), BigInteger.ZERO.toByteArray(), BigInteger.ZERO.toByteArray() };
				}
				lb.addResponse(port, requestID, res);
			}
		}
	}

	public void init(char[] password, String alias, KeyStore ks) {

		BigInteger timestamp = null;

		ck = new KeyManagement();

		// Initializes a connection to the Server
		connectToServer();

		// Generate a new key pair
		if (ks == null) {
			try {
				ck.generateKeyPair(password, alias);
				System.out.println("init: generating new key pair!");
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		// Extracts the key pair
		else {
			try {
				ck.getKeys(ks, password, alias);
				System.out.println("init: extracting key pair!");
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		try {
			// data sent ==> [ Client_Public_Key, Signature ]
			ArrayList<byte[]> data = server.init(ck.getPublicK(), ck.signature(ck.getPublicK().getEncoded()));
			// data received ==> [ Server_Public_Key, Session_Key, userID, Nonce, IV, Signature ]

			// Server's public key
			serverKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(data.get(0)));

			// Verifies Signature verifySignature(SK_pub, signature, SK_pub, Ks,
			// userID, Nonce, IV)
			if (!ck.verifySignature(serverKey, data.get(5), data.get(0), data.get(1), data.get(2), data.get(3),
					data.get(4))) {
				throw new SignatureWrongException();
			}

			// Session Key ciphered
			byte[] sessionKeyCiphered = data.get(1);

			// Deciphering of the session_key w/ server_public_key
			Cipher decipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			decipher.init(Cipher.DECRYPT_MODE, ck.getPrivateK());
			byte[] aux = decipher.doFinal(sessionKeyCiphered);

			sessionKey = new SecretKeySpec(aux, 0, aux.length, "AES");

			// IV
			byte[] iv = data.get(4);
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			// UserID ciphered
			byte[] userIDCiphered = data.get(2);

			// Nounce ciphered
			byte[] nounceCiphered = data.get(3);

			// Deciphering of the userID and nounce w/ session_key
			Cipher simetricCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			simetricCipher.init(Cipher.DECRYPT_MODE, sessionKey, ivspec);
			byte[] userIDDeciphered = simetricCipher.doFinal(userIDCiphered);
			byte[] nounceDeciphered = simetricCipher.doFinal(nounceCiphered);

			// Store UserID
			userID = new BigInteger(userIDDeciphered);

			// Store given nonce
			nounce = new BigInteger(nounceDeciphered);

		} catch (RemoteException e) {
			Thread.currentThread().interrupt();
			System.out.println("ERROR: Connection ERROR > TERMINATING THREAD " + port);
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
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
	}

	public void register_user() {

		try {
			// Generate new IV
			SecureRandom random = new SecureRandom();
			final byte[] iv = new byte[16];
			random.nextBytes(iv);
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			// Increment nounce
			nounce = nounce.shiftLeft(2);

			// Cipher userID w/ server_pub_key
			Cipher assimetricCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			assimetricCipher.init(Cipher.ENCRYPT_MODE, serverKey);

			final byte[] userIDCiphered = assimetricCipher.doFinal(userID.toByteArray());

			// Cipher nounce w/ session_key
			Cipher simetricCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			simetricCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivspec);

			final byte[] nounceCiphered = simetricCipher.doFinal(nounce.toByteArray());

			// Signature of all data [ CKpub, E(userID), E(nonce) & IV ]
			final byte[] signature = ck.signature(ck.getPublicK().getEncoded(), userIDCiphered, nounceCiphered, iv);

			// data sent ==> [ Client_Public_Key, User_ID, Nounce, IV,
			// Signature]
			server.register(ck.getPublicK(), userIDCiphered, nounceCiphered, iv, signature);

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
		} catch (RemoteException e) {
			Thread.currentThread().interrupt();
			System.out.println("ERROR: Connection ERROR > TERMINATING THREAD " + port);
			// e.printStackTrace();
		}

	}

	public void save_password(byte[] domain, byte[] username, byte[] password, byte[] timestamp, byte[]... write_rank) {

		byte[] userIDCiphered = null, passCiphered = null, domainCiphered = null, usernameCiphered = null,
				timestampCiphered = null, readIDCiphered = null, nounceCiphered = null, writeRankCiphered = null;

		nounce = nounce.shiftLeft(2);

		readID = readID.add(BigInteger.ONE);

		try {
			// Cipher UserID & Password with Public Key
			Cipher assimetricCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			assimetricCipher.init(Cipher.ENCRYPT_MODE, serverKey);

			userIDCiphered = assimetricCipher.doFinal(userID.toByteArray());

			assimetricCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			assimetricCipher.init(Cipher.ENCRYPT_MODE, ck.getPublicK());

			passCiphered = assimetricCipher.doFinal(password);

			// Generate a random IV
			SecureRandom random = new SecureRandom();
			byte[] iv = new byte[16];
			random.nextBytes(iv);
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			// Digest of Domain and Username
			byte[] domainHash = ck.digest(domain);
			byte[] usernameHash = ck.digest(username);

			// Signature of value [ H(domain), H(username), E(password),
			// timestamp ]
			byte[] valueSignature = ck.signature(domainHash, usernameHash, passCiphered, timestamp);

			// Cipher domain, username, password & nounce with session key
			Cipher simetricCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			simetricCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivspec);

			passCiphered = simetricCipher.doFinal(passCiphered);
			domainCiphered = simetricCipher.doFinal(domainHash);
			usernameCiphered = simetricCipher.doFinal(usernameHash);
			timestampCiphered = simetricCipher.doFinal(timestamp);
			readIDCiphered = simetricCipher.doFinal(readID.toByteArray());
			nounceCiphered = simetricCipher.doFinal(nounce.toByteArray());

			if (write_rank.length == 0) {
				writeRankCiphered = simetricCipher.doFinal(userID.toByteArray());
			} else {
				writeRankCiphered = simetricCipher.doFinal(write_rank[0]);
			}

			// Signature of all data [ E(userID), E(H(domain)), E(H(username)),
			// E(E(password)) & IV ]
			byte[] signature = ck.signature(userIDCiphered, domainCiphered, usernameCiphered, passCiphered,
					timestampCiphered, writeRankCiphered, valueSignature, iv, nounceCiphered);

			// Data sending ==> [ CKpub, User_ID, E(H(domain)), E(H(username)),
			// E(E(password)), IV, signature ]
			server.put(ck.getPublicK(), userIDCiphered, domainCiphered, usernameCiphered, passCiphered,
					timestampCiphered, writeRankCiphered, valueSignature, iv, nounceCiphered, signature);

		} catch (RemoteException e) {
			Thread.currentThread().interrupt();
			System.out.println("ERROR: Connection ERROR > TERMINATING THREAD " + port);
			// e.printStackTrace();
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
		} catch (InvalidTimestampException e) {

		}
	}

	public byte[][] retrieve_password(byte[] domain, byte[] username) {

		byte[] password = null, password_aux = null, userIDCiphered = null, domainEncryp = null, usernameEncryp = null,
				nounceEncryp = null, readIDEncryp = null, timestampDecipher = null, readIDDeciphered = null,
				nounceDeciphered = null, writeRankDecipher = null;
		ArrayList<byte[]> data = new ArrayList<byte[]>();

		nounce = nounce.shiftLeft(2);

		readID = readID.add(BigInteger.ONE);

		try {
			// Cipher UserID & Password with Public Key
			Cipher assimetricCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			assimetricCipher.init(Cipher.ENCRYPT_MODE, serverKey);

			userIDCiphered = assimetricCipher.doFinal(userID.toByteArray());

			// Generate a random IV
			SecureRandom random = new SecureRandom();
			byte[] iv = new byte[16];
			random.nextBytes(iv);
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			// Digest of Domain and Username
			byte[] domainHash = ck.digest(domain);
			byte[] usernameHash = ck.digest(username);

			// Cipher domain & username with session key
			Cipher simetricCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			simetricCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivspec);

			domainEncryp = simetricCipher.doFinal(domainHash);
			usernameEncryp = simetricCipher.doFinal(usernameHash);
			nounceEncryp = simetricCipher.doFinal(nounce.toByteArray());
			readIDEncryp = simetricCipher.doFinal(readID.toByteArray());

			// Signature of all data Public_Key, E(H(domain)), E(H(username)),
			// E(Nonce) & IV
			byte[] signature = ck.signature(ck.getPublicK().getEncoded(), userIDCiphered, readIDEncryp, domainEncryp,
					usernameEncryp, nounceEncryp, iv);

			// Data sending ==> [ CKpub, E(user_id), E(read_id), E(H(domain)),
			// E(H(username)), IV, E(nounce), signature ]
			data = server.get(ck.getPublicK(), userIDCiphered, readIDEncryp, domainEncryp, usernameEncryp, iv,
					nounceEncryp, signature);
			// Data received ==> [ password, timestamp, write_rank,
			// valueSignature, read_id, nounce, iv, signature ]
			
			if(data == null) {
				nounce = nounce.shiftLeft(2);
				System.out.println(port + " Domain or Username Doesnt Exist!");
				return null;
			}

			// Verifies Signature - verifySignature(public_key, signature,
			// password, nonce, iv)
			if (!ck.verifySignature(serverKey, data.get(7), data.get(0), data.get(1), data.get(2), data.get(3),
					data.get(4), data.get(5), data.get(6))) {
				throw new SignatureWrongException();
			}

			// Extracting IV
			byte[] passwordCipher = data.get(0);

			byte[] timestampCipher = data.get(1);

			byte[] writeRankCipher = data.get(2);

			byte[] valueSignature = data.get(3);

			byte[] readIDCipher = data.get(4);

			iv = data.get(6);

			ivspec = new IvParameterSpec(iv);

			// Extracting nounce
			nounceEncryp = data.get(5);

			// Decipher password with Session Key

			// COM CBC
			// Cipher firstDecipher =
			// Cipher.getInstance("AES/CBC/PKCS5Padding");
			// firstDecipher.init(Cipher.DECRYPT_MODE, sessionKey, ivspec);

			// COM ECB
			Cipher simetricDecipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			simetricDecipher.init(Cipher.DECRYPT_MODE, sessionKey);

			password_aux = simetricDecipher.doFinal(passwordCipher);
			timestampDecipher = simetricDecipher.doFinal(timestampCipher);
			writeRankDecipher = simetricDecipher.doFinal(writeRankCipher);
			readIDDeciphered = simetricDecipher.doFinal(readIDCipher);
			nounceDeciphered = simetricDecipher.doFinal(nounceEncryp);

			BigInteger rid = new BigInteger(readIDDeciphered);

			if (readID.compareTo(rid) != 0) {
				throw new InconcistencyException();
			}

			if (!ck.verifySignature(ck.getPublicK(), valueSignature, domainHash, usernameHash, password_aux,
					timestampDecipher)) {
				throw new SignatureWrongException();
			}

			// Decipher Password with Private Key
			Cipher assimetricDecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			assimetricDecipher.init(Cipher.DECRYPT_MODE, ck.getPrivateK());
			password = assimetricDecipher.doFinal(password_aux);

			// Verify nounce
			BigInteger bg = new BigInteger(nounceDeciphered);

			// Check nonce
			if (!bg.equals(nounce.shiftLeft(2))) {
				throw new InvalidNounceException();
			}

			nounce = nounce.shiftLeft(2);

		} catch (RemoteException e) {
			Thread.currentThread().interrupt();
			System.out.println("ERROR: Connection ERROR > TERMINATING THREAD " + port);
			// e.printStackTrace();
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

		return new byte[][] { password, timestampDecipher, writeRankDecipher };
	}

	public void close() {
		server = null;
		ck = null;
		serverKey = null;
		sessionKey = null;
		System.out.println("close: session closed!");
	}

	// Connection to the server
	private void connectToServer() {
		if (System.getSecurityManager() == null) {
			System.setSecurityManager(new SecurityManager());
		}
		try {
			server = (ServerService) Naming.lookup("//localhost:" + port + "/ServerService");
			System.out.println("Server found!, Port: " + port);
		} catch (Exception e) {
			System.out.println("Ups...something is wrong: " + e.getMessage());
		}
	}

}