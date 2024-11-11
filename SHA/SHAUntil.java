package SHA;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHAUntil {

	public static String sha1(String input) throws NoSuchAlgorithmException {
		return hashString(input, "SHA-1");
	}

	public static String sha256(String input) throws NoSuchAlgorithmException {
		return hashString(input, "SHA-256");
	}

	public static String sha512(String input) throws NoSuchAlgorithmException {
		return hashString(input, "SHA-512");
	}

	private static String hashString(String input, String algorith) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(algorith);
		byte[] hashBytes = md.digest(input.getBytes());
		StringBuilder sb = new StringBuilder();
		for (byte b : hashBytes) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}
}
