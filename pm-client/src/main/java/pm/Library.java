package pm;

import java.math.BigInteger;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Library {

	private ServerService server = null;

	private KeyManagement ck = null;

	private PublicKey serverKey = null;
	private SecretKey sessionKey = null;
	
	private BigInteger nouce = null;

	public void init(char[] password, String alias, KeyStore... ks) {

		ck = new KeyManagement();

		// Initializes a connection to the Server
		connectToServer();
		// Generate a new key pair
		if (ks.length == 0) {
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
				ck.getKeys(ks[0], alias, password);
				System.out.println("init: extracting key pair!");
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		try {
			// data ==> [ Server_Public_Key, Session_Key, Signature ]
			ArrayList<byte[]> data = server.init(ck.getPublicK());

			// Server's public key
			serverKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(data.get(0)));

			// Verifies Signature
			if (!ck.verifySignature(serverKey, data.get(2), data.get(1))) {
				System.out.println("init: signature wrong!");
				return;
			}

			// Session key ciphered
			byte[] sessionKeyCiphered = data.get(1);

			// Deciphering of the session key
			Cipher decipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			decipher.init(Cipher.DECRYPT_MODE, ck.getPrivateK());
			byte[] aux = decipher.doFinal(sessionKeyCiphered);

			sessionKey = new SecretKeySpec(aux, 0, aux.length, "AES");

			// IV
			byte[] iv = data.get(3);
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			// Nounce
			byte[] nounceCiphered = data.get(4);
			
			// Deciphering of the nounce
			Cipher simetricCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			simetricCipher.init(Cipher.DECRYPT_MODE, sessionKey, ivspec);
			byte[] nounceDeciphered = simetricCipher.doFinal(nounceCiphered);
			
			nouce = new BigInteger(nounceDeciphered);
			nouce = nouce.shiftLeft(2);
			
		} catch (RemoteException e) {
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
		}
	}

	public void register_user() {

		SecureRandom random = new SecureRandom();
		byte[] iv = new byte[16];
		random.nextBytes(iv);
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		
		try {
			Cipher simetricCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			simetricCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivspec);
			byte[] nounceCiphered = simetricCipher.doFinal(nouce.toByteArray());
			
			server.register(ck.getPublicK(), nounceCiphered, iv);
			System.out.println("register: user registered!");
			
		} catch (RemoteException e) {
			e.printStackTrace();
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

	}

	public void save_password(byte[] domain, byte[] username, byte[] password) {

		byte[] passEncryp = null, domainEncry = null, usernameEncry = null;

		try {
			// Cipher Password with Public Key
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, ck.getPublicK());
			passEncryp = cipher.doFinal(password);

			// Generate a random IV
			SecureRandom random = new SecureRandom();
			byte[] iv = new byte[16];
			random.nextBytes(iv);
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			// Digest of Domain and Username
			byte[] domainHash = ck.digest(domain);
			byte[] usernameHash = ck.digest(username);

			// Cipher domain, username & password with session key
			Cipher simetricCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			simetricCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivspec);

			passEncryp = simetricCipher.doFinal(passEncryp);
			domainEncry = simetricCipher.doFinal(domainHash);
			usernameEncry = simetricCipher.doFinal(usernameHash);

			// Signature of all data [ E(H(domain)), E(H(username)),
			// E(E(password)) & IV ]
			byte[] signature = ck.signature(domainEncry, usernameEncry, passEncryp, iv);

			// Data sending ==> [ CKpub, E(H(domain)), E(H(username)),
			// E(E(password)), IV, signature ]
			server.put(ck.getPublicK(), domainEncry, usernameEncry, passEncryp, iv, signature);

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
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
	}

	public byte[] retrieve_password(byte[] domain, byte[] username) {

		byte[] password = null, password_aux = null, domainEncryp = null, usernameEncryp = null;
		ArrayList<byte[]> data = new ArrayList<byte[]>();

		try {
			// Generate a random IV
			SecureRandom random = new SecureRandom();
			byte[] iv = new byte[16];
			random.nextBytes(iv);
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			// Digest of Domain and Username
			byte[] domainHash = ck.digest(domain);
			byte[] usernameHash = ck.digest(username);

			// Cipher domain & username with session key
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivspec);

			domainEncryp = cipher.doFinal(domainHash);
			usernameEncryp = cipher.doFinal(usernameHash);

			// Signature of all data, E(H(domain)), E(H(username)) & IV
			byte[] signature = ck.signature(domainEncryp, usernameEncryp, iv);

			// Data sending ==> [ CKpub, E(H(domain)), E(H(username)), IV,
			// signature ]
			data = server.get(ck.getPublicK(), domainEncryp, usernameEncryp, iv, signature);
			// Data received ==> [ password, iv, signature ]

			// Verifies Signature - verifySignature(public_key, signature,
			// password, iv)
			if (!ck.verifySignature(serverKey, data.get(2), data.get(0), data.get(1))) {
				throw new SignatureWrongException();
			}

			// Extracting IV
			byte[] passwordCipher = data.get(0);
			iv = data.get(1);

			ivspec = new IvParameterSpec(iv);

			// Decipher password with Session Key
			// COM CBC
			// Cipher firstDecipher =
			// Cipher.getInstance("AES/CBC/PKCS5Padding");
			// firstDecipher.init(Cipher.DECRYPT_MODE, sessionKey, ivspec);

			// COM ECB
			Cipher firstDecipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			firstDecipher.init(Cipher.DECRYPT_MODE, sessionKey);

			password_aux = firstDecipher.doFinal(passwordCipher);

			// Decipher Password with Private Key
			Cipher decipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			decipher.init(Cipher.DECRYPT_MODE, ck.getPrivateK());
			password = decipher.doFinal(password_aux);

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
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		return password;
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
			server = (ServerService) Naming.lookup("//localhost:10000/ServerService");
			System.out.println("Server found!");
		} catch (Exception e) {
			System.out.println("Ups...something is wrong: " + e.getMessage());
		}
	}

}
