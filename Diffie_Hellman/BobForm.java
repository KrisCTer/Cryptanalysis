package Diffie_Hellman;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JTextArea;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import javax.swing.JLabel;
import java.awt.Font;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.swing.SwingConstants;
import javax.swing.UIManager;

import java.awt.event.ActionListener;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.awt.event.ActionEvent;

public class BobForm extends javax.swing.JFrame {

	private JFrame frame;
	KeyAgreement bobKeyAgree;
	PublicKey alicePubKey;
	SecretKey bobDesKey;
	Cipher bobCipher;
	private JTextArea txt_bobKey;
	private JTextArea txt_aliceKey;
	private JTextArea txt_SharedSecret;
	private JTextArea txt_EncryptSharedSecret;

	@SuppressWarnings("unchecked")

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					BobForm window = new BobForm();
					window.frame.setVisible(true);
					UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public BobForm() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 650, 350);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);

		JButton btn_bobKeyGenerate = new JButton("Bob's Key Generate");
		btn_bobKeyGenerate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Bob's Key Generate") {
					btn_BobKeyGenerateActionPerformed(e);
				}
			}
		});
		btn_bobKeyGenerate.setFont(new Font("Tahoma", Font.PLAIN, 13));
		btn_bobKeyGenerate.setBounds(466, 74, 160, 35);
		frame.getContentPane().add(btn_bobKeyGenerate);

		txt_bobKey = new JTextArea();
		txt_bobKey.setBounds(171, 74, 285, 35);
		frame.getContentPane().add(txt_bobKey);

		JLabel lblNewLabel = new JLabel("Bob's Key");
		lblNewLabel.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel.setBounds(10, 74, 151, 35);
		frame.getContentPane().add(lblNewLabel);

		JLabel lblNewLabel_1 = new JLabel("Alice's Key");
		lblNewLabel_1.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_1.setBounds(10, 119, 151, 35);
		frame.getContentPane().add(lblNewLabel_1);

		txt_aliceKey = new JTextArea();
		txt_aliceKey.setBounds(171, 119, 285, 35);
		frame.getContentPane().add(txt_aliceKey);

		JButton btn_aliceKeyDisplay = new JButton("Alice's Key Display");
		btn_aliceKeyDisplay.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Alice's Key Display") {
					btn_AliceKeyDisplayActionPerformed(e);
				}
			}
		});
		btn_aliceKeyDisplay.setFont(new Font("Tahoma", Font.PLAIN, 13));
		btn_aliceKeyDisplay.setBounds(466, 119, 160, 35);
		frame.getContentPane().add(btn_aliceKeyDisplay);

		JLabel lblNewLabel_2 = new JLabel("Shared Secret");
		lblNewLabel_2.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_2.setBounds(10, 164, 151, 35);
		frame.getContentPane().add(lblNewLabel_2);

		txt_SharedSecret = new JTextArea();
		txt_SharedSecret.setBounds(171, 164, 285, 35);
		frame.getContentPane().add(txt_SharedSecret);

		JButton btn_makeSecretKey = new JButton("Make Secret Key");
		btn_makeSecretKey.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Make Secret Key") {
					btn_makeSecretKeyActionPerformed(e);
				}
			}
		});
		btn_makeSecretKey.setFont(new Font("Tahoma", Font.PLAIN, 13));
		btn_makeSecretKey.setBounds(466, 164, 160, 35);
		frame.getContentPane().add(btn_makeSecretKey);

		JLabel lblNewLabel_3 = new JLabel("Encrypt Shared Secret");
		lblNewLabel_3.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_3.setBounds(10, 209, 151, 35);
		frame.getContentPane().add(lblNewLabel_3);

		txt_EncryptSharedSecret = new JTextArea();
		txt_EncryptSharedSecret.setBounds(171, 209, 285, 35);
		frame.getContentPane().add(txt_EncryptSharedSecret);

		JButton btn_encryptSecretKey = new JButton("Encrypt Secret Key");
		btn_encryptSecretKey.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Encrypt Secret Key") {
					btn_encryptSecretKeyActionPerformed(e);
				}
			}
		});
		btn_encryptSecretKey.setFont(new Font("Tahoma", Font.PLAIN, 13));
		btn_encryptSecretKey.setBounds(466, 209, 160, 35);
		frame.getContentPane().add(btn_encryptSecretKey);

		JButton btn_run = new JButton("Run Encrypt/Decrypt Form");
		btn_run.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Run Encrypt/Decrypt Form") {
					btn_RunEncryptDecryptFormActionPerformed(e);
				}
			}
		});
		btn_run.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btn_run.setBounds(171, 268, 285, 35);
		frame.getContentPane().add(btn_run);

		JLabel lblNewLabel_4 = new JLabel("Bob Form (D-H)");
		lblNewLabel_4.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel_4.setFont(new Font("Tahoma", Font.BOLD, 20));
		lblNewLabel_4.setBounds(10, 10, 616, 35);
		frame.getContentPane().add(lblNewLabel_4);
	}

	private void btn_BobKeyGenerateActionPerformed(ActionEvent e) {
		try {
			boolean read = false;
			java.nio.file.Path dirPath = Paths.get("src/Diffie_Hellman");
			if (!java.nio.file.Files.exists(dirPath)) {
				java.nio.file.Files.createDirectories(dirPath);
			}
			while (!read) {
				try (FileInputStream fis = new FileInputStream(dirPath.resolve("A.pub").toFile())) {
					read = true;
				} catch (Exception ex) {
					ex.printStackTrace();
				}
			}
			byte[] alicePubKeyEnc;
			try (FileInputStream fis = new FileInputStream(dirPath.resolve("A.pub").toFile())) {
				alicePubKeyEnc = new byte[fis.available()];
				fis.read(alicePubKeyEnc);
			}

			KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);
			this.alicePubKey = bobKeyFac.generatePublic(x509KeySpec);
			DHParameterSpec dhParamSpec = ((DHPublicKey) alicePubKey).getParams();
			KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
			bobKpairGen.initialize(dhParamSpec);
			KeyPair bobKpair = bobKpairGen.generateKeyPair();
			this.bobKeyAgree = KeyAgreement.getInstance("DH");
			this.bobKeyAgree.init(bobKpair.getPrivate());
			byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();
			try (FileOutputStream fos = new FileOutputStream(dirPath.resolve("B.pub").toFile())) {
				fos.write(bobPubKeyEnc);
			}
			this.txt_bobKey.setText(java.util.Base64.getEncoder().encodeToString(bobPubKeyEnc));
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	private void btn_AliceKeyDisplayActionPerformed(ActionEvent e) {
		try {
			byte[] bkeyP;
			try (FileInputStream fis = new FileInputStream(Paths.get("src/Diffie_Hellman/A.pub").toFile())) {
				bkeyP = new byte[fis.available()];
				fis.read(bkeyP);
			}
			this.txt_aliceKey.setText(bkeyP.toString());
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	private void btn_makeSecretKeyActionPerformed(ActionEvent e) {
		try {
			this.bobKeyAgree.doPhase(this.alicePubKey, true);
			byte[] bobSharedSecret = this.bobKeyAgree.generateSecret();
			this.txt_SharedSecret.setText(CryptoUtil.toHexString(bobSharedSecret));
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	private void btn_encryptSecretKeyActionPerformed(ActionEvent e) {
		try {
			this.bobKeyAgree.doPhase(alicePubKey, true);
			byte[] shareSecret = this.bobKeyAgree.generateSecret();
			this.txt_EncryptSharedSecret.setText(CryptoUtil.toHexString(shareSecret));
			MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			byte[] desKeyBytes = Arrays.copyOf(sha256.digest(shareSecret), 8);
			SecretKeySpec desKeySpec = new SecretKeySpec(desKeyBytes, "DES");
			this.txt_EncryptSharedSecret.setText(Base64.getEncoder().encodeToString(desKeySpec.getEncoded()));
			String fileName = "src/Diffie_Hellman/B.txt";
			try (BufferedWriter bw = new BufferedWriter(new FileWriter(fileName))) {
				bw.write(Base64.getEncoder().encodeToString(desKeySpec.getEncoded()));
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	private void btn_RunEncryptDecryptFormActionPerformed(ActionEvent e) {
		View_DESCS des = new View_DESCS();
		des.frame.setVisible(true);
	}
}
