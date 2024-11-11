package Diffie_Hellman;

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

import DES.DESCipher;

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

public class View_DESCS extends javax.swing.JFrame {

	JFrame frame;
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
					View_DESCS window = new View_DESCS();
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
	public View_DESCS() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 790, 520);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);

		JButton btnSaveToFile = new JButton("Save to File");
		btnSaveToFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Save to File") {
					btn_saveToFileActionPerformed(e);
				}
			}
		});
		btnSaveToFile.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnSaveToFile.setBounds(280, 413, 209, 52);
		frame.getContentPane().add(btnSaveToFile);

		JButton btnEncrypt = new JButton("Encrypt");
		btnEncrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Encrypt") {
					btn_encryptActionPerformed(e);
				}
			}
		});
		btnEncrypt.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnEncrypt.setBounds(25, 331, 209, 52);
		frame.getContentPane().add(btnEncrypt);

		JButton btnOpenFile = new JButton("Open File");
		btnOpenFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Open File") {
					btn_openFileActionPerformed(e);
				}
			}
		});
		btnOpenFile.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnOpenFile.setBounds(280, 331, 209, 52);
		frame.getContentPane().add(btnOpenFile);

		JButton btnDecrypt = new JButton("Decrypt");
		btnDecrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Decrypt") {
					btn_decryptActionPerformed(e);
				}
			}
		});
		btnDecrypt.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnDecrypt.setBounds(25, 413, 209, 52);
		frame.getContentPane().add(btnDecrypt);

		txt_PlainText = new JTextArea();
		txt_PlainText.setBounds(142, 41, 624, 105);
		frame.getContentPane().add(txt_PlainText);

		txt_Key = new JTextArea();
		txt_Key.setBounds(142, 156, 624, 27);
		frame.getContentPane().add(txt_Key);

		txt_cipherText = new JTextArea();
		txt_cipherText.setBounds(142, 193, 624, 105);
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

		JLabel Elliptic = new JLabel("DESCS");
		Elliptic.setHorizontalAlignment(SwingConstants.CENTER);
		Elliptic.setFont(new Font("Tahoma", Font.BOLD, 20));
		Elliptic.setBounds(10, 0, 756, 38);
		frame.getContentPane().add(Elliptic);

		JButton btnOpenAliceKey = new JButton("Open Alice's Key");
		btnOpenAliceKey.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Open Alice's Key") {
					btn_OpenAliceKeyActionPerformed(e);
				}
			}
		});
		btnOpenAliceKey.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnOpenAliceKey.setBounds(537, 331, 209, 52);
		frame.getContentPane().add(btnOpenAliceKey);

		JButton btnOpenBobKey = new JButton("Open Bob's Key");
		btnOpenBobKey.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Open Bob's Key") {
					btn_OpenBobKeyActionPerformed(e);
				}
			}
		});
		btnOpenBobKey.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnOpenBobKey.setBounds(537, 413, 209, 52);
		frame.getContentPane().add(btnOpenBobKey);
	}

	private void btn_OpenBobKeyActionPerformed(ActionEvent e) {
		try {
			BufferedReader br = null;
			String fileName = "src/Diffie_Hellman/B.txt";
			br = new BufferedReader(new FileReader(fileName));
			StringBuffer sb = new StringBuffer();

			JOptionPane.showMessageDialog(null, "File Opened Successfully.");
			char[] ca = new char[5];
			while (br.ready()) {
				int len = br.read(ca);
				sb.append(ca, 0, len);
			}
			br.close();
			String chuoi = sb.toString();
			this.txt_Key.setText(chuoi);
		} catch (Exception ex) {
			Logger.getLogger(View_DESCS.class.getName()).log(Level.SEVERE, null, ex);
		}

	}

	private void btn_OpenAliceKeyActionPerformed(ActionEvent e) {
		try {
			BufferedReader br = null;
			String fileName = "src/Diffie_Hellman/A.txt";
			br = new BufferedReader(new FileReader(fileName));
			StringBuffer sb = new StringBuffer();

			JOptionPane.showMessageDialog(null, "File Opened Successfully.");
			char[] ca = new char[5];
			while (br.ready()) {
				int len = br.read(ca);
				sb.append(ca, 0, len);
			}
			br.close();
			String chuoi = sb.toString();
			this.txt_Key.setText(chuoi);
		} catch (Exception ex) {
			Logger.getLogger(View_DESCS.class.getName()).log(Level.SEVERE, null, ex);
		}
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

	private void btn_encryptActionPerformed(ActionEvent e) {
		try {
			String plainText = this.txt_PlainText.getText();
			String secretKey = this.txt_Key.getText();
			String encryptedText = DESCipher.encrypt(plainText, secretKey);
			this.txt_cipherText.setText(encryptedText);
		} catch (Exception ex) {
			JOptionPane.showMessageDialog(this.frame, "Error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
		}
	}

	private void btn_decryptActionPerformed(ActionEvent e) {
		try {
			String cipherText = this.txt_cipherText.getText();
			String secretKey = this.txt_Key.getText();
			String decryptedText = DESCipher.decrypt(cipherText, secretKey);
			this.txt_PlainText.setText(decryptedText);
		} catch (Exception ex) {
			JOptionPane.showMessageDialog(this.frame, "Error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
		}
	}
}
