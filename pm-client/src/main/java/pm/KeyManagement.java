package pm;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class KeyManagement {

	//Tenho de repensar isto, porque para varios utilizadores ao mesmo tempo nao funciona
	//ArrayList<PublicKey> pkList = new ArrayList<PublicKey>();
	protected PublicKey pk;

	public void generateKeyPair(char[] password, String alias) throws Exception {

		// Generate RSA key
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair keypair = keyGen.genKeyPair();

		// PrivateKey privateKey = keypair.getPrivate();
		// PublicKey publicKey = keypair.getPublic();

		new GenCert().generateCertificate(keypair, password, alias);

	}

	public void getPublicKey(KeyStore ks, String alias, char[] password) throws Exception{
		
		//Open the KeyStore file
		FileInputStream fis = new FileInputStream("keystorefile.jce");
		//Create an instance of KeyStore of type “JCEKS” 
		ks = KeyStore.getInstance("JCEKS");
		//Load the key entries from the file into the KeyStore object.
		ks.load(fis, password); 
		fis.close();
		//Get the key with the given alias.
		//Key k = ks.getKey(alias, password);
		pk = ks.getCertificate(alias).getPublicKey();
	}
	
	public PublicKey getPk() {
		return pk;
	}

}
