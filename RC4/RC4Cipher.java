package RC4;

public class RC4Cipher {
	private byte[] S = new byte[256];
	private byte[] T = new byte[256];
	private int keyLen;

	public RC4Cipher(byte[] key) {
		keyLen = key.length;
		for (int i = 0; i < 256; i++) {
			S[i] = (byte) i;
			T[i] = key[i % keyLen];
		}

		int j = 0;
		for (int i = 0; i < 256; i++) {
			j = (j + S[i] + T[i]) & 0xFF;
			swap(S, i, j);
		}
	}

	private void swap(byte[] arr, int i, int j) {
		byte temp = arr[i];
		arr[i] = arr[j];
		arr[j] = temp;
	}

	public byte[] encrypt(byte[] plainText) {
		byte[] cipherText = new byte[plainText.length];
		int i = 0, j = 0;

		for (int k = 0; k < plainText.length; k++) {
			i = (i + 1) & 0xFF;
			j = (j + S[i]) & 0xFF;
			swap(S, i, j);
			int t = (S[i] + S[j]) & 0xFF;
			cipherText[k] = (byte) (plainText[k] ^ S[t]);
		}
		return cipherText;
	}

	public byte[] decrypt(byte[] cipherText) {
		return encrypt(cipherText);
	}
}
