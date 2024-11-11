package RSA;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JButton;
import javax.swing.JFileChooser;

import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.math.BigInteger;
import java.awt.event.ActionEvent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.UIManager;
import javax.swing.filechooser.FileNameExtensionFilter;

import java.awt.Font;
import javax.swing.SwingConstants;

public class View_RSA {

	private JFrame frame;
	private JTextField plainText;
	private JTextField cipherText;
	RSACipher rsa = new RSACipher(1024);
	BigInteger n = null;
	BigInteger d = null;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					View_RSA window = new View_RSA();
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
	public View_RSA() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 447, 300);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);

		JButton Encrypt = new JButton("Encrypt");
		Encrypt.setFont(new Font("Tahoma", Font.PLAIN, 13));
		Encrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Encrypt") {
					btn_encryptActionPerformed(e);
				}
			}
		});
		Encrypt.setBounds(46, 205, 85, 21);
		frame.getContentPane().add(Encrypt);

		JButton Decrypt = new JButton("Decrypt");
		Decrypt.setFont(new Font("Tahoma", Font.PLAIN, 13));
		Decrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Decrypt") {
					btn_decryptActionPerformed(e);
				}
			}
		});
		Decrypt.setBounds(314, 205, 85, 21);
		frame.getContentPane().add(Decrypt);

		JLabel plaintext = new JLabel("Plain Text");
		plaintext.setFont(new Font("Tahoma", Font.PLAIN, 13));
		plaintext.setBounds(10, 60, 59, 13);
		frame.getContentPane().add(plaintext);

		JLabel lblNewLabel_2 = new JLabel("Ciphertext");
		lblNewLabel_2.setFont(new Font("Tahoma", Font.PLAIN, 13));
		lblNewLabel_2.setBounds(10, 148, 59, 13);
		frame.getContentPane().add(lblNewLabel_2);

		plainText = new JTextField();
		plainText.setBounds(79, 44, 320, 46);
		frame.getContentPane().add(plainText);
		plainText.setColumns(10);

		cipherText = new JTextField();
		cipherText.setColumns(10);
		cipherText.setBounds(79, 134, 320, 41);
		frame.getContentPane().add(cipherText);

		JLabel lblNewLabel = new JLabel("RSA");
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel.setFont(new Font("Tahoma", Font.BOLD, 16));
		lblNewLabel.setBounds(79, 10, 320, 24);
		frame.getContentPane().add(lblNewLabel);
	}

	private void btn_encryptActionPerformed(ActionEvent evt) {
		String plainText = this.plainText.getText();
		n = rsa.getN();
		d = rsa.getD();

		BigInteger[] cipherText = rsa.encrypt(plainText);
		StringBuilder bf = new StringBuilder();
		for (BigInteger ct : cipherText) {
			bf.append(ct.toString(16).toUpperCase()).append(" ");
		}
		String message = bf.toString().trim();
		this.cipherText.setText(message);
	}

	private void btn_decryptActionPerformed(ActionEvent evt) {
		String[] ctString = this.cipherText.getText().split(" ");
		BigInteger[] cipherText = new BigInteger[ctString.length];

		for (int i = 0; i < ctString.length; i++) {
			cipherText[i] = new BigInteger(ctString[i], 16);
		}
		String plainText = rsa.decrypt(cipherText, d, n);
		this.plainText.setText(plainText);
	}

}
