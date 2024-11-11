package Vingenere;

public class VingenereCipher {
	public static String encript(String text, String key) {
		return vingenereCipher(text, key, true);
	}

	public static String decript(String text, String key) {
		return vingenereCipher(text, key, false);
	}

	private static String vingenereCipher(String text, String key, boolean encript) {
		StringBuffer result = new StringBuffer();
		key = key.toLowerCase();
		int keyLength = key.length();
		int keyIndex = 0;
		for (char character : text.toCharArray()) {
			if (Character.isLetter(character)) {
				char base = Character.isUpperCase(character) ? 'A' : 'a';
				int shift = key.charAt(keyIndex % keyLength) - 'a';
				if (!encript)
					shift = 26 - shift;
				result.append((char) ((character - base + shift) % 26 + base));
				keyIndex++;
			} else
				result.append(character);
		}
		return result.toString();
	}
}
