package Diffie_Hellman;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JTextArea;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
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

public class AliceForm extends javax.swing.JFrame {

	private JFrame frame;
	KeyAgreement aliceKeyAgree;
	PublicKey bobPubKey;
	SecretKey aliceDesKey;
	Cipher aliceCipher;
	private JTextArea txt_aliceKey;
	private JTextArea txt_bobKey;
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
					AliceForm window = new AliceForm();
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
	public AliceForm() {
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

		JButton btn_aliceKeyGenerate = new JButton("Alice's Key Generate");
		btn_aliceKeyGenerate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Alice's Key Generate") {
					btn_AliceKeyGenerateActionPerformed(e);
				}
			}
		});
		btn_aliceKeyGenerate.setFont(new Font("Tahoma", Font.PLAIN, 13));
		btn_aliceKeyGenerate.setBounds(466, 74, 160, 35);
		frame.getContentPane().add(btn_aliceKeyGenerate);

		txt_aliceKey = new JTextArea();
		txt_aliceKey.setBounds(171, 74, 285, 35);
		frame.getContentPane().add(txt_aliceKey);

		JLabel lblNewLabel = new JLabel("Alice's Key");
		lblNewLabel.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel.setBounds(10, 74, 151, 35);
		frame.getContentPane().add(lblNewLabel);

		JLabel lblNewLabel_1 = new JLabel("Bob's Key");
		lblNewLabel_1.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_1.setBounds(10, 119, 151, 35);
		frame.getContentPane().add(lblNewLabel_1);

		txt_bobKey = new JTextArea();
		txt_bobKey.setBounds(171, 119, 285, 35);
		frame.getContentPane().add(txt_bobKey);

		JButton btn_bobKeyDisplay = new JButton("Bob's Key Display");
		btn_bobKeyDisplay.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Bob's Key Display") {
					btn_bobKeyDisplayActionPerformed(e);
				}
			}
		});
		btn_bobKeyDisplay.setFont(new Font("Tahoma", Font.PLAIN, 13));
		btn_bobKeyDisplay.setBounds(466, 119, 160, 35);
		frame.getContentPane().add(btn_bobKeyDisplay);

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

		JLabel lblNewLabel_4 = new JLabel("Alice Form (D-H)");
		lblNewLabel_4.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel_4.setFont(new Font("Tahoma", Font.BOLD, 20));
		lblNewLabel_4.setBounds(10, 10, 616, 35);
		frame.getContentPane().add(lblNewLabel_4);
	}

	private void btn_AliceKeyGenerateActionPerformed(ActionEvent e) {
		try {
			AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
			paramGen.init(512);
			AlgorithmParameters params = paramGen.generateParameters();
			DHParameterSpec dhSkipParamSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);
			System.out.println("Generating a DH Keypair...");
			KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
			aliceKpairGen.initialize(dhSkipParamSpec);
			KeyPair aliceKpair = aliceKpairGen.generateKeyPair();
			System.out.println("Initializing the KeyAgreement Engine with DH private key");
			this.aliceKeyAgree = KeyAgreement.getInstance("DH");
			this.aliceKeyAgree.init(aliceKpair.getPrivate());
			byte[] alivePubKeyEnc = aliceKpair.getPublic().getEncoded();
			java.nio.file.Path dirPath = Paths.get("src/Diffie_Hellman");
			if (!java.nio.file.Files.exists(dirPath)) {
				java.nio.file.Files.createDirectories(dirPath);
			}
			try (FileOutputStream fos = new FileOutputStream(dirPath.resolve("A.pub").toFile())) {
				fos.write(alivePubKeyEnc);
			}
			this.txt_aliceKey.setText(java.util.Base64.getEncoder().encodeToString(alivePubKeyEnc));
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	private void btn_bobKeyDisplayActionPerformed(ActionEvent e) {
		try {
			byte[] bkeyP;
			try (FileInputStream fis = new FileInputStream(Paths.get("src/Diffie_Hellman/B.pub").toFile())) {
				bkeyP = new byte[fis.available()];
				fis.read(bkeyP);
			}
			this.txt_bobKey.setText(bkeyP.toString());
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	private void btn_makeSecretKeyActionPerformed(ActionEvent e) {
		try {
			byte[] bobPubKeyEnc;
			try (FileInputStream fis = new FileInputStream(Paths.get("src/Diffie_Hellman/B.pub").toFile())) {
				bobPubKeyEnc = new byte[fis.available()];
				fis.read(bobPubKeyEnc);
			}
			KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
			this.bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
			System.out.println("Executing PHASE1 of key agreement...");
			this.aliceKeyAgree.doPhase(bobPubKey, true);
			byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();

			System.out.println("Khoa chung: secret (DEBUG ONLY): " + CryptoUtil.toHexString(aliceSharedSecret));
			this.txt_SharedSecret.setText(CryptoUtil.toHexString(aliceSharedSecret));
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	private void btn_encryptSecretKeyActionPerformed(ActionEvent e) {
		try {
			this.aliceKeyAgree.doPhase(bobPubKey, true);
			byte[] shareSecret = this.aliceKeyAgree.generateSecret();
			this.txt_EncryptSharedSecret.setText(CryptoUtil.toHexString(shareSecret));
			MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			byte[] desKeyBytes = Arrays.copyOf(sha256.digest(shareSecret), 8);
			SecretKeySpec desKeySpec = new SecretKeySpec(desKeyBytes, "DES");
			this.txt_EncryptSharedSecret.setText(Base64.getEncoder().encodeToString(desKeySpec.getEncoded()));
			String fileName = "src/Diffie_Hellman/A.txt";
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
