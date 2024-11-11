package MD5;

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

public class View_MD5 extends javax.swing.JFrame {

	private JFrame frame;
	private JTextArea txt_PlainText;
	private JTextArea txt_Hash;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					View_MD5 window = new View_MD5();
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
	public View_MD5() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 590, 370);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);

		JButton btnMD5Hash = new JButton("MD5Hash");
		btnMD5Hash.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "MD5Hash") {
					btn_MD5HashActionPerformed(e);
				}
			}
		});
		btnMD5Hash.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnMD5Hash.setBounds(20, 271, 546, 52);
		frame.getContentPane().add(btnMD5Hash);

		txt_PlainText = new JTextArea();
		txt_PlainText.setBounds(142, 41, 389, 105);
		frame.getContentPane().add(txt_PlainText);

		txt_Hash = new JTextArea();
		txt_Hash.setBounds(142, 156, 389, 105);
		frame.getContentPane().add(txt_Hash);

		JLabel lblCiphertext = new JLabel("Hash");
		lblCiphertext.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblCiphertext.setBounds(10, 156, 122, 105);
		frame.getContentPane().add(lblCiphertext);

		JLabel lblNewLabel_3_1 = new JLabel("PlainText");
		lblNewLabel_3_1.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_3_1.setBounds(10, 41, 122, 105);
		frame.getContentPane().add(lblNewLabel_3_1);

		JLabel Elliptic = new JLabel("MD5 HASH DEMO");
		Elliptic.setHorizontalAlignment(SwingConstants.CENTER);
		Elliptic.setFont(new Font("Tahoma", Font.BOLD, 20));
		Elliptic.setBounds(10, 0, 556, 38);
		frame.getContentPane().add(Elliptic);
	}

	private void btn_MD5HashActionPerformed(ActionEvent e) {
		String input = this.txt_PlainText.getText();
		String md5Hash = MD5Until.md5(input);
		this.txt_Hash.setText(md5Hash);
	}

}
