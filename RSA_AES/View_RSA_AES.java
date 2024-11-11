package RSA_AES;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.swing.AbstractButton;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.JTextArea;
import java.awt.Font;
import java.awt.HeadlessException;

import javax.swing.SwingConstants;
import javax.swing.UIManager;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.awt.event.ActionEvent;

public class View_RSA_AES extends javax.swing.JFrame {

	private JFrame frame;
	private RSA_AES_Cipher rsaCipher;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	private JTextArea txt_PlainText;
	private JTextArea txt_publicKey;
	private JTextArea txt_cipherText;
	private JTextArea txt_privateKey;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					View_RSA_AES window = new View_RSA_AES();
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
	public View_RSA_AES() {
		initialize();
		try {
			rsaCipher = new RSA_AES_Cipher();
			Security.addProvider(new BouncyCastleProvider());
		} catch (Exception ex) {
			Logger.getLogger(View_RSA_AES.class.getName()).log(Level.SEVERE, null, ex);
		}
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 590, 559);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);

		JButton btnGenerateKeys = new JButton("Generate keys");
		btnGenerateKeys.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Generate keys") {
					btn_generateKeysActionPerformed(e);
				}
			}
		});
		btnGenerateKeys.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnGenerateKeys.setBounds(45, 356, 209, 52);
		frame.getContentPane().add(btnGenerateKeys);

		JButton btnEncrypt = new JButton("Encrypt");
		btnEncrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Encrypt") {
					btn_encryptActionPerformed(e);
				}
			}
		});
		btnEncrypt.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnEncrypt.setBounds(322, 356, 209, 52);
		frame.getContentPane().add(btnEncrypt);

		JButton btnLoadKeys = new JButton("Load keys");
		btnLoadKeys.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Load keys") {
					btn_loadKeysActionPerformed(e);
				}
			}
		});
		btnLoadKeys.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnLoadKeys.setBounds(45, 438, 209, 52);
		frame.getContentPane().add(btnLoadKeys);

		JButton btnDecrypt = new JButton("Decrypt");
		btnDecrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Decrypt") {
					btn_decryptActionPerformed(e);
				}
			}
		});
		btnDecrypt.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnDecrypt.setBounds(322, 438, 209, 52);
		frame.getContentPane().add(btnDecrypt);

		txt_PlainText = new JTextArea();
		txt_PlainText.setBounds(142, 41, 389, 105);
		frame.getContentPane().add(txt_PlainText);

		txt_publicKey = new JTextArea();
		txt_publicKey.setBounds(142, 156, 389, 27);
		frame.getContentPane().add(txt_publicKey);

		txt_cipherText = new JTextArea();
		txt_cipherText.setBounds(142, 230, 389, 105);
		frame.getContentPane().add(txt_cipherText);

		txt_privateKey = new JTextArea();
		txt_privateKey.setBounds(142, 193, 389, 27);
		frame.getContentPane().add(txt_privateKey);

		JLabel lblPublicKey = new JLabel("Public Key");
		lblPublicKey.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblPublicKey.setBounds(10, 156, 122, 27);
		frame.getContentPane().add(lblPublicKey);

		JLabel lblCiphertext = new JLabel("CipherText");
		lblCiphertext.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblCiphertext.setBounds(10, 230, 122, 105);
		frame.getContentPane().add(lblCiphertext);

		JLabel lblNewLabel_3_1 = new JLabel("PlainText");
		lblNewLabel_3_1.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_3_1.setBounds(10, 41, 122, 105);
		frame.getContentPane().add(lblNewLabel_3_1);

		JLabel lblNewLabel_1_1 = new JLabel("Private Key");
		lblNewLabel_1_1.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_1_1.setBounds(10, 193, 122, 27);
		frame.getContentPane().add(lblNewLabel_1_1);

		JLabel Elliptic = new JLabel("RSA-AES");
		Elliptic.setHorizontalAlignment(SwingConstants.CENTER);
		Elliptic.setFont(new Font("Tahoma", Font.BOLD, 20));
		Elliptic.setBounds(10, 0, 556, 38);
		frame.getContentPane().add(Elliptic);
	}

	protected void btn_generateKeysActionPerformed(ActionEvent e) {
		try {
			rsaCipher = new RSA_AES_Cipher();
			this.txt_publicKey.setText(rsaCipher.getPublicKey().toString());
			this.txt_privateKey.setText(rsaCipher.getPrivateKey().toString());

			JFileChooser publicKeyChooser = new JFileChooser();
			publicKeyChooser.setDialogTitle("Save Public Key File");
			int publicKeyChooserResult = publicKeyChooser.showOpenDialog(this.frame);
			if (publicKeyChooserResult == JFileChooser.APPROVE_OPTION) {
				File publicKeyFile = publicKeyChooser.getSelectedFile();
				try (FileWriter writer = new FileWriter(publicKeyFile.getAbsolutePath())) {
					writer.write(rsaCipher.getPublicKey().toString());
					JOptionPane.showMessageDialog(this.frame, "Public Key saved to file successfully.", "Success",
							JOptionPane.INFORMATION_MESSAGE);
				} catch (Exception ex) {
					JOptionPane.showMessageDialog(this.frame, "Error saved Public Key file: " + ex.getMessage(),
							"Error", JOptionPane.ERROR_MESSAGE);
				}
			}

			JFileChooser privateKeyChooser = new JFileChooser();
			privateKeyChooser.setDialogTitle("Save Private Key File");
			int privateKeyChooserResult = privateKeyChooser.showOpenDialog(this.frame);
			if (privateKeyChooserResult == JFileChooser.APPROVE_OPTION) {
				File privateKeyFile = privateKeyChooser.getSelectedFile();
				try (FileWriter writer = new FileWriter(privateKeyFile.getAbsolutePath())) {
					writer.write(rsaCipher.getPrivateKey().toString());
					JOptionPane.showMessageDialog(this.frame, "Private Key saved to file successfully.", "Success",
							JOptionPane.INFORMATION_MESSAGE);
				} catch (Exception ex) {
					JOptionPane.showMessageDialog(this.frame, "Error saved Private Key file: " + ex.getMessage(),
							"Error", JOptionPane.ERROR_MESSAGE);
				}
			}

		} catch (Exception ex) {
			Logger.getLogger(View_RSA_AES.class.getName()).log(Level.SEVERE, null, ex);
			JOptionPane.showMessageDialog(this.frame, "Error generating RSA key pair: " + ex.getMessage(), "Error",
					JOptionPane.ERROR_MESSAGE);
		}

	}

	protected void btn_loadKeysActionPerformed(ActionEvent e) {
		try {
			JFileChooser publicKeyChooser = new JFileChooser();
			publicKeyChooser.setDialogTitle("Load Public Key File");
			int publicKeyChooserResult = publicKeyChooser.showOpenDialog(this.frame);
			if (publicKeyChooserResult == JFileChooser.APPROVE_OPTION) {
				File publicKeyFile = publicKeyChooser.getSelectedFile();
				String publicKeyContent = readFile(publicKeyFile);
				this.txt_privateKey.setText(publicKeyContent);
			}

			JFileChooser privateKeyChooser = new JFileChooser();
			privateKeyChooser.setDialogTitle("Load Private Key File");
			int privateKeyChooserResult = privateKeyChooser.showOpenDialog(this.frame);
			if (privateKeyChooserResult == JFileChooser.APPROVE_OPTION) {
				File privateKeyFile = privateKeyChooser.getSelectedFile();
				String privateKeyContent = readFile(privateKeyFile);
				this.txt_privateKey.setText(privateKeyContent);
			}
		} catch (HeadlessException | IOException ex) {
			Logger.getLogger(View_RSA_AES.class.getName()).log(Level.SEVERE, null, ex);
			JOptionPane.showMessageDialog(this.frame, "Error loading keys : " + ex.getMessage(), "Error",
					JOptionPane.ERROR_MESSAGE);
		}

	}

	private String readFile(File file) throws FileNotFoundException, IOException {
		StringBuilder contentBuilder = new StringBuilder();
		try (BufferedReader br = new BufferedReader(new FileReader(file))) {
			String line;
			while ((line = br.readLine()) != null) {
				contentBuilder.append(line).append("\n");
			}
		}
		return contentBuilder.toString();
	}

	protected void btn_encryptActionPerformed(ActionEvent e) {
		try {
			String plainText = this.txt_PlainText.getText();
			byte[] encryptedBytes = rsaCipher.encrypt(plainText);
			String encryptedText = new String(encryptedBytes, StandardCharsets.ISO_8859_1);
			this.txt_cipherText.setText(encryptedText);
		} catch (IllegalBlockSizeException | BadPaddingException ex) {
			Logger.getLogger(View_RSA_AES.class.getName()).log(Level.SEVERE, null, ex);
			JOptionPane.showMessageDialog(this.frame, "Error encrypting: " + ex.getMessage(), "Error",
					JOptionPane.ERROR_MESSAGE);
		} catch (Exception ex) {
			Logger.getLogger(View_RSA_AES.class.getName()).log(Level.SEVERE, null, ex);
			JOptionPane.showMessageDialog(this.frame, "Error encrypting: " + ex.getMessage(), "Error",
					JOptionPane.ERROR_MESSAGE);
		}
	}

	protected void btn_decryptActionPerformed(ActionEvent e) {
		try {
			byte[] combined = this.txt_cipherText.getText().getBytes(StandardCharsets.ISO_8859_1);
			String decryptedText = this.rsaCipher.decrypt(combined);
			this.txt_PlainText.setText(decryptedText);
		} catch (IllegalBlockSizeException | BadPaddingException ex) {
			Logger.getLogger(View_RSA_AES.class.getName()).log(Level.SEVERE, null, ex);
			JOptionPane.showMessageDialog(this.frame, "Error encrypting: " + ex.getMessage(), "Error",
					JOptionPane.ERROR_MESSAGE);
		} catch (Exception ex) {
			Logger.getLogger(View_RSA_AES.class.getName()).log(Level.SEVERE, null, ex);
			JOptionPane.showMessageDialog(this.frame, "Error encrypting: " + ex.getMessage(), "Error",
					JOptionPane.ERROR_MESSAGE);
		}
	}
}
