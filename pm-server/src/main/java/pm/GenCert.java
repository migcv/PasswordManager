package pm;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import sun.security.x509.*;
import java.io.FileOutputStream;

/**
 * Created by mm on 08/03/2017.
 */
public class GenCert {


	public X509Certificate[] generateCertificate(KeyPair pair, char[] password, String alias) throws Exception {

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair keypair = keyGen.genKeyPair();

		// PrivateKey privateKey = keypair.getPrivate();
		// PublicKey publicKey = keypair.getPublic();

		X509CertInfo info = new X509CertInfo();
		Date from = new Date();
		Date to = new Date(from.getTime() + 365 * 86400000l); // 1 year
		CertificateValidity interval = new CertificateValidity(from, to);
		X500Name owner = new X500Name("C=PT, ST=SEC");

		info.set(X509CertInfo.VALIDITY, interval);
		info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new BigInteger(64, new SecureRandom())));
		info.set(X509CertInfo.SUBJECT, owner);
		info.set(X509CertInfo.ISSUER, owner);
		info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
		info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
		AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
		info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
		X509CertImpl cert = new X509CertImpl(info);
		cert.sign(pair.getPrivate(), "SHA256withRSA");
		algo = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
		info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
		cert = new X509CertImpl(info);
		cert.sign(keypair.getPrivate(), "SHA256withRSA");

		return new X509Certificate[] { cert };
	}
}