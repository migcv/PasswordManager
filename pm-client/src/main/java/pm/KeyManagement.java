package pm;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

public class KeyManagement {

	private PublicKey publicK;
	private PrivateKey privateK;

	public void generateKeyPair(char[] password, String alias) throws Exception {

		// Generate RSA key
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair keypair = keyGen.genKeyPair();

		privateK = keypair.getPrivate();
		publicK = keypair.getPublic();

		new GenCert().generateCertificate(keypair, password, alias);

	}

	public void getKeys(KeyStore ks, char[] password, String alias) throws Exception {

		// Get the key with the given alias.
		// Key k = ks.getKey(alias, password);
		publicK = ks.getCertificate(alias).getPublicKey();
		Key k = ks.getKey(alias, password);
		if (k instanceof PrivateKey) {
			privateK = (PrivateKey) k;
		}
	}

	public PublicKey getPublicK() {
		return publicK;
	}

	public PrivateKey getPrivateK() {
		return privateK;
	}

	public byte[] digest(byte[] message) throws NoSuchAlgorithmException {
		MessageDigest sha = MessageDigest.getInstance("SHA-256");
		sha.update(message);
		return sha.digest();
	}

	public byte[] signature(byte[]... arrays) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		byte[] toSend = concat(arrays);

		Signature rsaForSign = Signature.getInstance("SHA256withRSA");
		rsaForSign.initSign(privateK);
		rsaForSign.update(toSend);
		byte[] signature = rsaForSign.sign();
		return signature;
	}

	public boolean verifySignature(Key publicKey, byte[] signature, byte[]... data) {
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

	static byte[] concat(byte[]... arrays) {
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
}
