package Autokey;

public class AutokeyCipher {
	public static String encrypt(String plainText, String key) {
		plainText = plainText.toUpperCase();
		key = key.toUpperCase();

		StringBuilder cipherText = new StringBuilder();
		int keyIndex = 0;

		for (int i = 0; i < plainText.length(); i++) {
			char plainChar = plainText.charAt(i);

			if (Character.isLetter(plainChar)) {
				char keyChar;

				if (keyIndex < key.length()) {
					keyChar = key.charAt(keyIndex);
					keyIndex++;
				} else {
					keyChar = plainText.charAt(i - key.length());
				}

				int shift = keyChar - 'A';
				char encryptedChar = (char) ((plainChar - 'A' + shift) % 26 + 'A');
				cipherText.append(encryptedChar);
			} else {
				cipherText.append(plainChar);
			}
		}
		return cipherText.toString();
	}

	public static String decrypt(String cipherText, String key) {
		cipherText = cipherText.toUpperCase();
		key = key.toUpperCase();

		StringBuilder plainText = new StringBuilder();
		int keyIndex = 0;

		for (int i = 0; i < cipherText.length(); i++) {
			char cipherChar = cipherText.charAt(i);

			if (Character.isLetter(cipherChar)) {
				char keyChar;

				if (keyIndex < key.length()) {
					keyChar = key.charAt(keyIndex);
					keyIndex++;
				} else {
					keyChar = plainText.charAt(i - key.length());
				}

				int shift = keyChar - 'A';
				char decryptedChar = (char) ((cipherChar - 'A' - shift + 26) % 26 + 'A');
				plainText.append(decryptedChar);
			} else {
				plainText.append(cipherChar);
			}
		}
		return plainText.toString();
	}
}
