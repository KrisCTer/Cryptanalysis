package RSA_AES;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class RSA_AES_Cipher {
	private PublicKey publicKey;
	private PrivateKey privateKey;

	public RSA_AES_Cipher() throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair keyPair = keyGen.generateKeyPair();

		this.publicKey = keyPair.getPublic();
		this.privateKey = keyPair.getPrivate();
	}

	public byte[] encrypt(String plainText) throws Exception {
		SecretKey secretKey = generateAESKey();
		byte[] encryptedSymmetricKey = rsaEncrypt(secretKey.getEncoded());
		Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] encryptedData = aesCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
		byte[] combined = new byte[encryptedSymmetricKey.length + encryptedData.length];
		System.arraycopy(encryptedSymmetricKey, 0, combined, 0, encryptedSymmetricKey.length);
		System.arraycopy(encryptedData, 0, combined, encryptedSymmetricKey.length, encryptedData.length);
		return combined;
	}

	public String decrypt(byte[] combined) throws Exception {
		int symmetricKeyLength = 256;
		byte[] encryptedSymmetricKey = new byte[symmetricKeyLength];
		byte[] encryptedData = new byte[combined.length - symmetricKeyLength];
		System.arraycopy(combined, 0, encryptedSymmetricKey, 0, symmetricKeyLength);
		System.arraycopy(combined, symmetricKeyLength, encryptedData, 0, encryptedData.length);
		byte[] decryptedSymmetricKey = rsaDecrypt(encryptedSymmetricKey);
		SecretKey secretKey = new SecretKeySpec(decryptedSymmetricKey, "AES");
		Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] decryptedData = aesCipher.doFinal(encryptedData);
		return new String(decryptedData, StandardCharsets.UTF_8);
	}

	private SecretKey generateAESKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		return keyGenerator.generateKey();
	}

	private byte[] rsaEncrypt(byte[] encoded) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(encoded);
	}

	private byte[] rsaDecrypt(byte[] encryptedSymmetricKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(encryptedSymmetricKey);
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}
}
