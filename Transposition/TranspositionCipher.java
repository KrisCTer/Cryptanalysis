package Transposition;

import java.util.Arrays;

public class TranspositionCipher {
	public static String encrypt(String text, int[] key) {
		int numRows = (int) Math.ceil((double) text.length() / key.length);
		char[][] grid = new char[numRows][key.length];
		for (char[] row : grid) {
			Arrays.fill(row, ' ');
		}

		for (int i = 0; i < text.length(); i++) {
			grid[i / key.length][i % key.length] = text.charAt(i);
		}

		StringBuilder cipherText = new StringBuilder();
		for (int k : key) {
			for (int row = 0; row < numRows; row++) {
				if (grid[row][k - 1] != ' ') {
					cipherText.append(grid[row][k - 1]);
				}
			}
		}
		return cipherText.toString();
	}

	public static String decrypt(String text, int[] key) {
		int numRows = (int) Math.ceil((double) text.length() / key.length);
		char[][] grid = new char[numRows][key.length];
		for (char[] row : grid) {
			Arrays.fill(row, ' ');
		}
		int textIndex = 0;
		for (int k : key) {
			for (int row = 0; row < numRows; row++) {
				if (textIndex < text.length()) {
					grid[row][k - 1] = text.charAt(textIndex++);
				}
			}
		}

		StringBuilder plainText = new StringBuilder();
		for (int row = 0; row < numRows; row++) {
			for (int col = 0; col < key.length; col++) {
				if (grid[row][col] != ' ') {
					plainText.append(grid[row][col]);
				}
			}
		}

		return plainText.toString();
	}
}
