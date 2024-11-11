package TwoFish;

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
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.awt.event.ActionEvent;

public class View_TwoFish extends javax.swing.JFrame {

	private JFrame frame;
	private TwoFishCipher twoFish = new TwoFishCipher();
	private JTextArea txt_PlainText;
	private JTextArea txt_Key;
	private JTextArea txt_cipherText;
	private JTextArea txt_IV;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					View_TwoFish window = new View_TwoFish();
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
	public View_TwoFish() {
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

		JButton btnOpenFile = new JButton("Open File");
		btnOpenFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Open File") {
					btn_openFileActionPerformed(e);
				}
			}
		});
		btnOpenFile.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnOpenFile.setBounds(45, 438, 209, 52);
		frame.getContentPane().add(btnOpenFile);

		JButton btnSaveToFile = new JButton("Save To File");
		btnSaveToFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Save To File") {
					btn_saveToFileActionPerformed(e);
				}
			}
		});
		btnSaveToFile.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnSaveToFile.setBounds(322, 438, 209, 52);
		frame.getContentPane().add(btnSaveToFile);

		txt_PlainText = new JTextArea();
		txt_PlainText.setBounds(142, 41, 389, 105);
		frame.getContentPane().add(txt_PlainText);

		txt_Key = new JTextArea();
		txt_Key.setBounds(142, 156, 389, 27);
		frame.getContentPane().add(txt_Key);

		txt_cipherText = new JTextArea();
		txt_cipherText.setBounds(142, 230, 389, 105);
		frame.getContentPane().add(txt_cipherText);

		txt_IV = new JTextArea();
		txt_IV.setBounds(142, 193, 389, 27);
		frame.getContentPane().add(txt_IV);

		JLabel lblPublicKey = new JLabel("Key");
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

		JLabel lblNewLabel_1_1 = new JLabel("IV");
		lblNewLabel_1_1.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_1_1.setBounds(10, 193, 122, 27);
		frame.getContentPane().add(lblNewLabel_1_1);

		JLabel Elliptic = new JLabel("TWO FISH");
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
		try {
			String plainText = this.txt_PlainText.getText();
			byte[] key = this.txt_Key.getText().getBytes(StandardCharsets.UTF_8);
			byte[] iv = this.txt_IV.getText().getBytes(StandardCharsets.UTF_8);

			byte[] cipherText = twoFish.encrypt(plainText, key, iv);
			String encryptedText = Base64.getEncoder().encodeToString(cipherText);

			this.txt_cipherText.setText(encryptedText);
		} catch (UnsupportedEncodingException ex) {
			JOptionPane.showMessageDialog(this.frame, "Unsuppported encoding : " + ex.getMessage(), "Error",
					JOptionPane.ERROR_MESSAGE);
		} catch (Exception ex) {
			Logger.getLogger(View_TwoFish.class.getName()).log(Level.SEVERE, null, ex);
			JOptionPane.showMessageDialog(this.frame, "Error encrypting : " + ex.getMessage(), "Error",
					JOptionPane.ERROR_MESSAGE);
		}
	}

	protected void btn_decryptActionPerformed(ActionEvent e) {
		try {
			String cipherText = this.txt_cipherText.getText();
			byte[] key = this.txt_Key.getText().getBytes(StandardCharsets.UTF_8);
			byte[] iv = this.txt_IV.getText().getBytes(StandardCharsets.UTF_8);

			byte[] decodedCipherText = Base64.getDecoder().decode(cipherText);
			String decryptedText = twoFish.decrypt(decodedCipherText, key, iv);

			this.txt_PlainText.setText(decryptedText);
		} catch (Exception ex) {
			Logger.getLogger(View_TwoFish.class.getName()).log(Level.SEVERE, null, ex);
			JOptionPane.showMessageDialog(this.frame, "Error decrypting : " + ex.getMessage(), "Error",
					JOptionPane.ERROR_MESSAGE);
		}
	}
}
