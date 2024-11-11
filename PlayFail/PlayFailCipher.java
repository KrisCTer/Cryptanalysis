package PlayFail;

import java.util.HashSet;
import java.util.Set;

public class PlayFailCipher {

	private static char[][] keyMatrix;
	private static final int MATRIX_SIZE = 5;

	public PlayFailCipher(String key) {
		keyMatrix = generateKeyMatrix(key);
	}

	private char[][] generateKeyMatrix(String key) {
		char[][] matrix = new char[MATRIX_SIZE][MATRIX_SIZE];
		Set<Character> used = new HashSet<>();
		StringBuilder keyBuilder = new StringBuilder();

		for (char ch : key.toCharArray()) {
			if (Character.isLetter(ch)) {
				ch = Character.toUpperCase(ch);
				if (ch == 'J')
					ch = 'I';
				if (!used.contains(ch)) {
					keyBuilder.append(ch);
					used.add(ch);
				}
			}
		}

		for (char ch = 'A'; ch <= 'Z'; ch++) {
			if (ch == 'J')
				continue;
			if (!used.contains(ch)) {
				keyBuilder.append(ch);
				used.add(ch);
			}
		}

		int index = 0;
		for (int row = 0; row < MATRIX_SIZE; row++) {
			for (int col = 0; col < MATRIX_SIZE; col++) {
				matrix[row][col] = keyBuilder.charAt(index++);
			}
		}

		return matrix;
	}

	private static String preprocessText(String text, boolean encode) {
		text = text.toUpperCase().replaceAll("[^A-Z]", "").replace("J", "I");
		StringBuilder sb = new StringBuilder(text);
		for (int i = 0; i < sb.length() - 1; i += 2)
			if (sb.charAt(i) == sb.charAt(i + 1))
				sb.insert(i + 1, 'X');
		if (sb.length() % 2 != 0)
			sb.append('X');
		return sb.toString();
	}

	public static String encript(String plaintext) {
		return processText(plaintext, true);
	}

	private static String processText(String text, boolean encrypt) {
		text = preprocessText(text, encrypt);
		StringBuilder result = new StringBuilder();

		for (int i = 0; i < text.length(); i += 2) {
			char a = text.charAt(i);
			char b = text.charAt(i + 1);
			int[] posA = findPosition(a);
			int[] posB = findPosition(b);

			if (posA[0] == posB[0]) {
				result.append(keyMatrix[posA[0]][(posA[1] + (encrypt ? 1 : 4)) % MATRIX_SIZE]);
				result.append(keyMatrix[posB[0]][(posB[1] + (encrypt ? 1 : 4)) % MATRIX_SIZE]);
			} else if (posA[1] == posB[1]) {
				result.append(keyMatrix[(posA[0] + (encrypt ? 1 : 4)) % MATRIX_SIZE][posA[1]]);
				result.append(keyMatrix[(posB[0] + (encrypt ? 1 : 4)) % MATRIX_SIZE][posB[1]]);
			} else {
				result.append(keyMatrix[posA[0]][posB[1]]);
				result.append(keyMatrix[posB[0]][posA[1]]);
			}
		}
		return result.toString();
	}

	public static String decript(String ciphertext) {
		StringBuilder plainText = new StringBuilder();
		ciphertext = ciphertext.toUpperCase().replaceAll("[^A-Z]", "");

		for (int i = 0; i < ciphertext.length(); i += 2) {
			char firstChar = ciphertext.charAt(i);
			char secondChar = ciphertext.charAt(i + 1);

			int[] pos1 = findPosition(firstChar);
			int[] pos2 = findPosition(secondChar);

			if (pos1[0] == pos2[0]) {
				plainText.append(keyMatrix[pos1[0]][(pos1[1] + 4) % 5]);
				plainText.append(keyMatrix[pos2[0]][(pos2[1] + 4) % 5]);
			} else if (pos1[1] == pos2[1]) {
				plainText.append(keyMatrix[(pos1[0] + 4) % 5][pos1[1]]);
				plainText.append(keyMatrix[(pos2[0] + 4) % 5][pos2[1]]);
			} else {
				plainText.append(keyMatrix[pos1[0]][pos2[1]]);
				plainText.append(keyMatrix[pos2[0]][pos1[1]]);
			}
		}

		for (int i = 0; i < plainText.length() - 1; i++)
			if (plainText.charAt(i) == 'X' && plainText.charAt(i - 1) == plainText.charAt(i + 1))
				plainText.deleteCharAt(i);
		if (plainText.charAt(plainText.length() - 1) == 'X')
			plainText.deleteCharAt(plainText.length() - 1);
		return plainText.toString();
	}

	private static int[] findPosition(char ch) {
		for (int row = 0; row < MATRIX_SIZE; row++)
			for (int col = 0; col < MATRIX_SIZE; col++)
				if (keyMatrix[row][col] == ch)
					return new int[] { row, col };
		return null;
	}

	public String getKeyMatrixAsString() {
		StringBuilder matrixString = new StringBuilder();
		for (int row = 0; row < MATRIX_SIZE; row++) {
			for (int col = 0; col < MATRIX_SIZE; col++) {
				matrixString.append(keyMatrix[row][col]).append(" ");
			}
			matrixString.append("\n");
		}
		return matrixString.toString();
	}
}
