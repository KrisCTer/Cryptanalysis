package HASH;

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
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.awt.event.ActionEvent;

public class View_FileHash extends javax.swing.JFrame {

	private JFrame frame;
	private JTextArea txt_Hash;

	private File seclectedFile;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					View_FileHash window = new View_FileHash();
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
	public View_FileHash() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 650, 250);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);

		JButton btnChooseFile = new JButton("Choose File");
		btnChooseFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Choose File") {
					btn_ChooseFileActionPerformed(e);
				}
			}
		});
		btnChooseFile.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnChooseFile.setBounds(10, 156, 200, 52);
		frame.getContentPane().add(btnChooseFile);

		txt_Hash = new JTextArea();
		txt_Hash.setBounds(142, 41, 488, 105);
		frame.getContentPane().add(txt_Hash);

		JLabel lblNewLabel_3_1 = new JLabel("Hash");
		lblNewLabel_3_1.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_3_1.setBounds(10, 41, 122, 105);
		frame.getContentPane().add(lblNewLabel_3_1);

		JLabel Elliptic = new JLabel("FILE HASH");
		Elliptic.setHorizontalAlignment(SwingConstants.CENTER);
		Elliptic.setFont(new Font("Tahoma", Font.BOLD, 20));
		Elliptic.setBounds(10, 0, 620, 38);
		frame.getContentPane().add(Elliptic);

		JButton btnFileHash = new JButton("File Hash");
		btnFileHash.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "File Hash") {
					btn_FileHashActionPerformed(e);
				}
			}
		});
		btnFileHash.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnFileHash.setBounds(220, 156, 200, 52);
		frame.getContentPane().add(btnFileHash);

		JButton btnSaveHash = new JButton("Save Hash");
		btnSaveHash.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Choose File") {
					btn_SaveHashActionPerformed(e);
				}
			}
		});
		btnSaveHash.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnSaveHash.setBounds(430, 156, 200, 52);
		frame.getContentPane().add(btnSaveHash);
	}

	private void btn_SaveHashActionPerformed(ActionEvent e) {
		JFileChooser fileChooser = new JFileChooser();
		int option = fileChooser.showSaveDialog(this);
		if (option == JFileChooser.APPROVE_OPTION) {
			File file = fileChooser.getSelectedFile();
			String content = this.txt_Hash.getText();
			if (!file.getName().toLowerCase().endsWith(".txt")) {
				file = new File(file.getParent(), file.getName() + ".txt");
			}
			try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
				writer.write(content);
				JOptionPane.showMessageDialog(this.frame, "File saved successfully.", "Success",
						JOptionPane.INFORMATION_MESSAGE);
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(this.frame, "Error saving file: " + ex.getMessage(), "Error",
						JOptionPane.ERROR_MESSAGE);
			}
		}

	}

	private void btn_FileHashActionPerformed(ActionEvent e) {
		if (this.seclectedFile == null) {
			JOptionPane.showMessageDialog(this.frame, "Please choose a file firt.", "Error", JOptionPane.ERROR_MESSAGE);
			return;
		}
		try {
			byte[] fileBytes = readFile(this.seclectedFile);
			String hash = calculateHash(fileBytes, "SHA-256");
			this.txt_Hash.setText(hash);
		} catch (IOException | NoSuchAlgorithmException ex) {
			JOptionPane.showMessageDialog(this.frame, "Error calculating hash: " + ex.getMessage(), "Error",
					JOptionPane.ERROR_MESSAGE);
		}
	}

	private String calculateHash(byte[] input, String algorithm) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(algorithm);
		byte[] hashBytes = md.digest(input);
		StringBuilder sb = new StringBuilder();
		for (byte b : hashBytes) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}

	private byte[] readFile(File file) throws IOException {
		try (FileInputStream fis = new FileInputStream(file)) {
			byte[] buffer = new byte[1024];
			int bytesRead;
			StringBuilder sb = new StringBuilder();
			while ((bytesRead = fis.read(buffer)) != -1) {
				sb.append(new String(buffer, 0, bytesRead));
			}
			return sb.toString().getBytes();
		}
	}

	private void btn_ChooseFileActionPerformed(ActionEvent e) {

		JFileChooser fileChooser = new JFileChooser();
		int result = fileChooser.showOpenDialog(this);
		if (result == JFileChooser.APPROVE_OPTION) {
			this.seclectedFile = fileChooser.getSelectedFile();
		}
	}

}
