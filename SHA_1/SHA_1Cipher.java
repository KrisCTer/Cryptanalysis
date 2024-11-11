package SHA_1;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SHA_1Cipher {

	// Hàm xoay trái (leftrotate) 32-bit
	private static int leftRotate(int value, int bits) {
		return (value << bits) | (value >>> (32 - bits));
	}

	// Triển khai SHA-1
	public static byte[] sha1(byte[] message) {
		// Khởi tạo các giá trị biến h0 - h4
		int h0 = 0x67452301;
		int h1 = 0xEFCDAB89;
		int h2 = 0x98BADCFE;
		int h3 = 0x10325476;
		int h4 = 0xC3D2E1F0;

		// Bước tiền xử lý (pre-processing)
		int messageLengthInBits = message.length * 8;
		int paddingLength = (448 - (messageLengthInBits + 1) % 512 + 512) % 512;
		int totalLength = messageLengthInBits + 1 + paddingLength + 64;

		ByteBuffer buffer = ByteBuffer.allocate(totalLength / 8);
		buffer.put(message); // Thêm thông điệp ban đầu
		buffer.put((byte) 0x80); // Thêm bit '1'
		while (buffer.position() % 64 != 56) { // Thêm bit '0' cho đến khi đạt 448 bit
			buffer.put((byte) 0x00);
		}
		buffer.putLong(messageLengthInBits); // Thêm độ dài thông điệp ban đầu (64-bit)

		// Xử lý từng khối 512-bit
		byte[] paddedMessage = buffer.array();
		for (int i = 0; i < paddedMessage.length; i += 64) {
			// Chia thành 16 từ 32-bit
			int[] w = new int[80];
			for (int j = 0; j < 16; j++) {
				w[j] = ByteBuffer.wrap(paddedMessage, i + j * 4, 4).getInt();
			}

			// Mở rộng thành 80 từ 32-bit
			for (int j = 16; j < 80; j++) {
				w[j] = leftRotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
			}

			// Khởi tạo các biến a, b, c, d, e
			int a = h0, b = h1, c = h2, d = h3, e = h4;

			// Vòng lặp chính
			for (int j = 0; j < 80; j++) {
				int f, k;
				if (j < 20) {
					f = (b & c) | ((~b) & d);
					k = 0x5A827999;
				} else if (j < 40) {
					f = b ^ c ^ d;
					k = 0x6ED9EBA1;
				} else if (j < 60) {
					f = (b & c) | (b & d) | (c & d);
					k = 0x8F1BBCDC;
				} else {
					f = b ^ c ^ d;
					k = 0xCA62C1D6;
				}

				int temp = leftRotate(a, 5) + f + e + k + w[j];
				e = d;
				d = c;
				c = leftRotate(b, 30);
				b = a;
				a = temp;
			}

			// Cộng kết quả của khối này vào hàm băm tạm thời
			h0 += a;
			h1 += b;
			h2 += c;
			h3 += d;
			h4 += e;
		}

		// Tạo hàm băm cuối cùng (160-bit)
		ByteBuffer hashBuffer = ByteBuffer.allocate(20);
		hashBuffer.putInt(h0);
		hashBuffer.putInt(h1);
		hashBuffer.putInt(h2);
		hashBuffer.putInt(h3);
		hashBuffer.putInt(h4);
		return hashBuffer.array();
	}

	public static void main(String[] args) {
		String input = "Chau Phuc Loi";
		byte[] hash = sha1(input.getBytes(StandardCharsets.UTF_8));

		// Xuất ra dạng thập lục phân (hex)
		StringBuilder hexString = new StringBuilder();
		for (byte b : hash) {
			hexString.append(String.format("%02x", b));
		}
		System.out.println("SHA-1 (Hex): " + hexString);

		// Xuất ra dạng Base64
		String base64Hash = Base64.getEncoder().encodeToString(hash);
		System.out.println("SHA-1 (Base64): " + base64Hash);
	}
}
