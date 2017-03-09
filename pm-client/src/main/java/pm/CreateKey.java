package pm;

import java.security.*;
import java.security.cert.X509Certificate;
import java.io.FileOutputStream;

public class CreateKey {

	public void generateKeyPair(char[] password, String alias) throws Exception {

		// Generate RSA key
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair keypair = keyGen.genKeyPair();

		// PrivateKey privateKey = keypair.getPrivate();
		// PublicKey publicKey = keypair.getPublic();

		new GenCert().generateCertificate(keypair, password, alias);

	}

	public void verifyKeyStore() {
		// TODO Auto-generated method stub

	}

}
