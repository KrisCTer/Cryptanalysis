package RC4;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.AbstractButton;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.JTextArea;
import java.awt.Font;
import javax.swing.SwingConstants;
import javax.swing.UIManager;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
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

public class View_RC4 extends javax.swing.JFrame {

	private JFrame frame;
	private RC4Cipher rc4;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	private JTextArea txt_PlainText;
	private JTextArea txt_Key;
	private JTextArea txt_cipherText;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					View_RC4 window = new View_RC4();
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
	public View_RC4() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 590, 559);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);

		JButton btnGenerateKeys = new JButton("Save to File");
		btnGenerateKeys.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Save to File") {
					btn_saveToFileActionPerformed(e);
				}
			}
		});
		btnGenerateKeys.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnGenerateKeys.setBounds(322, 438, 209, 52);
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
		btnEncrypt.setBounds(45, 356, 209, 52);
		frame.getContentPane().add(btnEncrypt);

		JButton btnLoadKeys = new JButton("Open File");
		btnLoadKeys.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Open File") {
					btn_openFileActionPerformed(e);
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
		btnDecrypt.setBounds(322, 356, 209, 52);
		frame.getContentPane().add(btnDecrypt);

		txt_PlainText = new JTextArea();
		txt_PlainText.setBounds(142, 41, 389, 105);
		frame.getContentPane().add(txt_PlainText);

		txt_Key = new JTextArea();
		txt_Key.setBounds(142, 156, 389, 27);
		frame.getContentPane().add(txt_Key);

		txt_cipherText = new JTextArea();
		txt_cipherText.setBounds(142, 193, 389, 105);
		frame.getContentPane().add(txt_cipherText);

		JLabel lblPublicKey = new JLabel("Key");
		lblPublicKey.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblPublicKey.setBounds(10, 156, 122, 27);
		frame.getContentPane().add(lblPublicKey);

		JLabel lblCiphertext = new JLabel("CipherText");
		lblCiphertext.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblCiphertext.setBounds(10, 193, 122, 105);
		frame.getContentPane().add(lblCiphertext);

		JLabel lblNewLabel_3_1 = new JLabel("PlainText");
		lblNewLabel_3_1.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_3_1.setBounds(10, 41, 122, 105);
		frame.getContentPane().add(lblNewLabel_3_1);

		JLabel Elliptic = new JLabel("RC4");
		Elliptic.setHorizontalAlignment(SwingConstants.CENTER);
		Elliptic.setFont(new Font("Tahoma", Font.BOLD, 20));
		Elliptic.setBounds(10, 0, 556, 38);
		frame.getContentPane().add(Elliptic);
	}

	protected void btn_openFileActionPerformed(ActionEvent e) {
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setDialogTitle("Open File containing Ciphertext");
		int userSelection = fileChooser.showOpenDialog(this.frame);
		if (userSelection == JFileChooser.APPROVE_OPTION) {
			File publicToOpen = fileChooser.getSelectedFile();
			try (BufferedReader reader = new BufferedReader(new FileReader(publicToOpen))) {
				StringBuilder cipherTextBuilder = new StringBuilder();
				String line;
				while ((line = reader.readLine()) != null) {
					cipherTextBuilder.append(line);
				}
				String cipherText = cipherTextBuilder.toString().trim();
				this.txt_cipherText.setText(cipherText);
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(this.frame, "Error opening file : " + ex.getMessage(), "Error",
						JOptionPane.ERROR_MESSAGE);
			}
		}

	}

	private void btn_saveToFileActionPerformed(ActionEvent e) {
		String cipherText = this.txt_cipherText.getText();
		JFileChooser fc = new JFileChooser();
		fc.setDialogTitle("Save Ciphertext to File");
		int userSelection = fc.showSaveDialog(this.frame);
		if (userSelection == JFileChooser.APPROVE_OPTION) {
			File fileToSave = fc.getSelectedFile();
			try (FileWriter fw = new FileWriter(fileToSave.getAbsolutePath() + ".txt")) {
				fw.write(cipherText);
				JOptionPane.showMessageDialog(this.frame, "Ciphertext saved to file successfully", "Success",
						JOptionPane.INFORMATION_MESSAGE);
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(this.frame, "Error saving file: " + ex.getMessage(), "Error",
						JOptionPane.ERROR_MESSAGE);
			}
		}
	}

	protected void btn_encryptActionPerformed(ActionEvent e) {
		String plainText = this.txt_PlainText.getText();
		byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);
		String key = this.txt_Key.getText();
		rc4 = new RC4Cipher(key.getBytes());
		byte[] cipherTextBytes = rc4.encrypt(plainTextBytes);
		String cipherText = bytesToHexString(cipherTextBytes);
		this.txt_cipherText.setText(cipherText);
	}

	protected void btn_decryptActionPerformed(ActionEvent e) {
		String cipherText = this.txt_cipherText.getText();
		byte[] cipherTextBytes = hexStringToByteArray(cipherText);
		String key = this.txt_Key.getText();
		rc4 = new RC4Cipher(key.getBytes());
		byte[] decryptedBytes = rc4.decrypt(cipherTextBytes);
		String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
		this.txt_PlainText.setText(decryptedText);
	}

	private static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	private String bytesToHexString(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02X", b));
		}
		return sb.toString();
	}
}
