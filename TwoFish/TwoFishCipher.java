package TwoFish;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.G3413CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class TwoFishCipher {
	private static final int BLOCK_SIZE = 16;
	private BlockCipher cipher = new G3413CBCBlockCipher(new TwofishEngine());

	public byte[] encrypt(String plainText, byte[] key, byte[] iv) throws Exception {
		PaddedBufferedBlockCipher paddedCipher = new PaddedBufferedBlockCipher(cipher);
		ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key), iv);
		paddedCipher.init(true, parameters);

		byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);
		int minSize = paddedCipher.getOutputSize(plainTextBytes.length);
		byte[] outBuf = new byte[minSize];
		int length1 = paddedCipher.processBytes(plainTextBytes, 0, plainTextBytes.length, outBuf, 0);
		int length2 = paddedCipher.doFinal(outBuf, length1);

		byte[] cipherText = new byte[length1 + length2];
		System.arraycopy(outBuf, 0, cipherText, 0, cipherText.length);
		return cipherText;
	}

	public String decrypt(byte[] cipherText, byte[] key, byte[] iv) throws Exception {
		PaddedBufferedBlockCipher paddedCipher = new PaddedBufferedBlockCipher(cipher);
		ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key), iv);
		paddedCipher.init(false, parameters);

		int minSize = paddedCipher.getOutputSize(cipherText.length);
		byte[] outBuf = new byte[minSize];
		int length1 = paddedCipher.processBytes(cipherText, 0, cipherText.length, outBuf, 0);
		int length2 = paddedCipher.doFinal(outBuf, length1);

		byte[] plainTextBytes = new byte[length1 + length2];
		System.arraycopy(outBuf, 0, plainTextBytes, 0, plainTextBytes.length);
		return new String(plainTextBytes, StandardCharsets.UTF_8);
	}
}
