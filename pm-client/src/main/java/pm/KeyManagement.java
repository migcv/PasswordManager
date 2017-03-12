package pm;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.io.FileInputStream;
import java.io.FileOutputStream;

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

	public void getKeys(KeyStore ks, String alias, char[] password) throws Exception{
		
		//Open the KeyStore file
		FileInputStream fis = new FileInputStream("keystorefile.jce");
		//Create an instance of KeyStore of type “JCEKS” 
		ks = KeyStore.getInstance("JCEKS");
		//Load the key entries from the file into the KeyStore object.
		ks.load(fis, password); 
		fis.close();
		//Get the key with the given alias.
		//Key k = ks.getKey(alias, password);
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

}
