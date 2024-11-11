package RSA;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;

public class RSADemo {
	public static void main(String[] args) throws IOException {
		int primeSize = 1024;
		RSACipher rsa = new RSACipher(primeSize);

		System.out.println("Key size: [" + primeSize + "]");
		System.out.println();
		System.out.println("Generate prime numbers p and q");
		System.out.println("p: [" + rsa.getP().toString(16).toUpperCase() + "]");
		System.out.println("q: [" + rsa.getQ().toString(16).toUpperCase() + "]");
		System.out.println();
		System.out.println("The public key is the pair (N,E) which will be published.");
		System.out.println("N: [" + rsa.getN().toString(16).toUpperCase() + "]");
		System.out.println("E: [" + rsa.getE().toString(16).toUpperCase() + "]");
		System.out.println();
		System.out.println("The private key is the pair (N,E) which will be kept private.");
		System.out.println("N: [" + rsa.getN().toString(16).toUpperCase() + "]");
		System.out.println("D: [" + rsa.getD().toString(16).toUpperCase() + "]");
		System.out.println();

		System.out.print("Please enter message (plaintext): ");
		String plainText = new BufferedReader(new InputStreamReader(System.in)).readLine();

		BigInteger[] cipherText = rsa.encrypt(plainText);
		System.out.print("Ciphertext: ");
		for (BigInteger cipherTextPart : cipherText) {
			System.out.print(cipherTextPart.toString(16).toUpperCase());
			System.out.print(" ");
		}
		System.out.println();

		String recoveredPlainText = rsa.decrypt(cipherText, rsa.getD(), rsa.getN());
		System.out.println("Recovered plaintext: " + recoveredPlainText);
	}
}
