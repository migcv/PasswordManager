package pm;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Random;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Utils implements Serializable {

	private static final long serialVersionUID = 1L;

	// Generate a session key
	public SecretKey createSessionKey() {
		KeyGenerator keyGenerator;
		SecretKey key = null;
		try {
			keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(128, new SecureRandom());
			key = keyGenerator.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return key;
	}

	// Checks if the signature is valid
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

	public byte[] diggestSalt(byte[] content, byte[] salt) {
		MessageDigest sha;
		byte[] res = null;
		try {
			sha = MessageDigest.getInstance("SHA-256");
			sha.update(concat(content, salt));
			res = sha.digest();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return res;
	}

	public BigInteger generateBigInteger() {
		Random rand = new SecureRandom();
		return new BigInteger(30000, rand);
	}

	// Auxiliary function for verifySignature, to join all data received from
	// the client
	public byte[] concat(byte[]... arrays) {
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
