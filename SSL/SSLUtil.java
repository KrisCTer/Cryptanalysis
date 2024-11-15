package SSL;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.sql.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class SSLUtil {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static KeyPair generateRSAKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		return keyPairGenerator.generateKeyPair();
	}

	public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String dn) throws Exception {
		long now = System.currentTimeMillis();
		Date startDate = new Date(now);

		X500Name dnName = new X500Name(dn);
		BigInteger certSerialNumber = new BigInteger(Long.toString(now));
		Date endDate = new Date(now + 365L * 24L * 60L * 60L * 1000L);

		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
		X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber,
				startDate, endDate, dnName, keyPair.getPublic());

		return new JcaX509CertificateConverter().setProvider("BC")
				.getCertificate(certificateBuilder.build(contentSigner));
	}

	public static String convertToPEM(X509Certificate certificate) throws Exception {
		StringBuilder pem = new StringBuilder();
		pem.append("-----BEGIN CERTIFICATE-----\n");
		pem.append(new String(java.util.Base64.getMimeEncoder().encode(certificate.getEncoded())));
		pem.append("-----END CERTIFICATE-----\n");
		return pem.toString();
	}
}
