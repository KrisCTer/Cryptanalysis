package AES;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AESCipher {
	private static final String ALGORITHM = "AES";
	private static final String ENCRYPTION_KEY = "encryptionKey";

	public static String encrypt(String plainText, String secretKey) throws NoSuchAlgorithmException,
			InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
		SecretKey key = generateKey(secretKey);
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(cipher.ENCRYPT_MODE, key);
		byte[] encryptBytes = cipher.doFinal(plainText.getBytes());
		return Base64.getEncoder().encodeToString(encryptBytes);
	}

	public static String decrypt(String cipherText, String secretKey) throws NoSuchAlgorithmException,
			InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
		SecretKey key = generateKey(secretKey);
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(cipher.DECRYPT_MODE, key);
		byte[] decodeBytes = Base64.getDecoder().decode(cipherText);
		byte[] decryptBytes = cipher.doFinal(decodeBytes);
		return new String(decryptBytes);
	}

	private static SecretKey generateKey(String secretKey) throws NoSuchAlgorithmException {
		byte[] keyBytes = secretKey.getBytes();
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ALGORITHM);
		return keySpec;
	}

	private static String generateRegistrationKey(String userName, String password) {
		return userName + ":" + password + ":" + ENCRYPTION_KEY;
	}

	public static void saveRegistrationKeyToFile(String registrationKey, String fileName) throws IOException {
		try (FileOutputStream fos = new FileOutputStream(fileName);
				ObjectOutputStream oos = new ObjectOutputStream(fos)) {
			oos.writeObject(registrationKey);
		}
	}

	private static String readRegistrationKeyToFile(String fileName) throws IOException, ClassNotFoundException {
		try (FileInputStream fis = new FileInputStream(fileName); ObjectInputStream ois = new ObjectInputStream(fis)) {
			return (String) ois.readObject();
		}
	}
}
