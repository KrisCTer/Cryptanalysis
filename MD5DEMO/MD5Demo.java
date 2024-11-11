package MD5DEMO;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class MD5Demo {

	private static final int[] s = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14,
			20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21,
			6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };

	private static final int[] K = { 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
			0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
			0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6,
			0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681,
			0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085,
			0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
			0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82,
			0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

	private static int a0 = 0x67452301;
	private static int b0 = 0xefcdab89;
	private static int c0 = 0x98badcfe;
	private static int d0 = 0x10325476;

	private static int leftRotate(int x, int c) {
		return (x << c) | (x >>> (32 - c));
	}

	public static String computeMD5(String message) {
		byte[] msgBytes = message.getBytes(StandardCharsets.UTF_8);

		int originalLengthBits = msgBytes.length * 8;
		int paddingLength = (56 - (msgBytes.length + 1) % 64) % 64;

		byte[] paddedMsg = Arrays.copyOf(msgBytes, msgBytes.length + 1 + paddingLength + 8);
		paddedMsg[msgBytes.length] = (byte) 0x80;

		for (int i = 0; i < 8; i++) {
			paddedMsg[paddedMsg.length - 8 + i] = (byte) (originalLengthBits >>> (8 * i));
		}

		for (int offset = 0; offset < paddedMsg.length; offset += 64) {
			int[] M = new int[16];
			for (int i = 0; i < 16; i++) {
				M[i] = ((paddedMsg[offset + i * 4] & 0xFF)) | ((paddedMsg[offset + i * 4 + 1] & 0xFF) << 8)
						| ((paddedMsg[offset + i * 4 + 2] & 0xFF) << 16)
						| ((paddedMsg[offset + i * 4 + 3] & 0xFF) << 24);
			}

			int A = a0, B = b0, C = c0, D = d0;

			for (int i = 0; i < 64; i++) {
				int F, g;
				if (i < 16) {
					F = (B & C) | (~B & D);
					g = i;
				} else if (i < 32) {
					F = (D & B) | (~D & C);
					g = (5 * i + 1) % 16;
				} else if (i < 48) {
					F = B ^ C ^ D;
					g = (3 * i + 5) % 16;
				} else {
					F = C ^ (B | ~D);
					g = (7 * i) % 16;
				}

				F = F + A + K[i] + M[g];
				A = D;
				D = C;
				C = B;
				B = B + leftRotate(F, s[i]);
			}

			a0 += A;
			b0 += B;
			c0 += C;
			d0 += D;
		}

		byte[] hash = new byte[16];
		int[] values = { a0, b0, c0, d0 };
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				hash[i * 4 + j] = (byte) (values[i] >>> (8 * j));
			}
		}

		StringBuilder hexString = new StringBuilder();
		for (byte b : hash) {
			hexString.append(String.format("%02x", b));
		}
		return hexString.toString();
	}

	public static void main(String[] args) {
		String message = "Chau Phuc Loi";
		String hash = computeMD5(message);
		System.out.println("MD5(\"" + message + "\") = " + hash);
	}
}
