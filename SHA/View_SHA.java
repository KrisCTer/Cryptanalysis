package SHA;

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
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.awt.event.ActionEvent;

public class View_SHA extends javax.swing.JFrame {

	private JFrame frame;
	private JTextArea txt_PlainText;
	private JTextArea txt_SHA_1;
	private JTextArea txt_SHA_256;
	private JTextArea txt_SHA_512;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					View_SHA window = new View_SHA();
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
	public View_SHA() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 600, 600);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);

		JButton btnSHAHash = new JButton("SHAHash");
		btnSHAHash.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "SHAHash") {
					btn_SHAHashActionPerformed(e);
				}
			}
		});
		btnSHAHash.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnSHAHash.setBounds(10, 501, 566, 52);
		frame.getContentPane().add(btnSHAHash);

		txt_PlainText = new JTextArea();
		txt_PlainText.setBounds(142, 41, 434, 105);
		frame.getContentPane().add(txt_PlainText);

		txt_SHA_1 = new JTextArea();
		txt_SHA_1.setBounds(142, 156, 434, 105);
		frame.getContentPane().add(txt_SHA_1);

		JLabel lblSHA_1 = new JLabel("SHA-1");
		lblSHA_1.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblSHA_1.setBounds(10, 156, 122, 105);
		frame.getContentPane().add(lblSHA_1);

		JLabel lblNewLabel_3_1 = new JLabel("PlainText");
		lblNewLabel_3_1.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_3_1.setBounds(10, 41, 122, 105);
		frame.getContentPane().add(lblNewLabel_3_1);

		JLabel Elliptic = new JLabel("SHA HASH DEMO");
		Elliptic.setHorizontalAlignment(SwingConstants.CENTER);
		Elliptic.setFont(new Font("Tahoma", Font.BOLD, 20));
		Elliptic.setBounds(10, 0, 556, 38);
		frame.getContentPane().add(Elliptic);

		txt_SHA_256 = new JTextArea();
		txt_SHA_256.setBounds(142, 271, 434, 105);
		frame.getContentPane().add(txt_SHA_256);

		JLabel lblSha_256 = new JLabel("SHA-256");
		lblSha_256.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblSha_256.setBounds(10, 271, 122, 105);
		frame.getContentPane().add(lblSha_256);

		txt_SHA_512 = new JTextArea();
		txt_SHA_512.setBounds(142, 386, 434, 105);
		frame.getContentPane().add(txt_SHA_512);

		JLabel lblSha_512 = new JLabel("SHA-512");
		lblSha_512.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblSha_512.setBounds(10, 386, 122, 105);
		frame.getContentPane().add(lblSha_512);
	}

	private void btn_SHAHashActionPerformed(ActionEvent e) {
		String plaintext = this.txt_PlainText.getText();
		if (plaintext.isEmpty()) {
			JOptionPane.showMessageDialog(this.frame, "Please enter plaintext");
			return;
		}
		try {
			String sha1Hash = SHAUntil.sha1(plaintext);
			this.txt_SHA_1.setText(sha1Hash);
			String sha256Hash = SHAUntil.sha256(plaintext);
			this.txt_SHA_256.setText(sha256Hash);
			String sha512Hash = SHAUntil.sha512(plaintext);
			this.txt_SHA_512.setText(sha512Hash);
		} catch (NoSuchAlgorithmException ex) {
			JOptionPane.showMessageDialog(this.frame, "Error calculating SHA hash: " + ex.getMessage());
		}
	}
}
