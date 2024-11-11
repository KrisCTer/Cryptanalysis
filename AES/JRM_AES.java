package AES;

import java.awt.Desktop.Action;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.SwingConstants;
import javax.swing.UIManager;

import java.awt.Font;
import java.awt.event.ActionEvent;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.swing.JTextField;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import java.awt.event.ActionListener;

public class JRM_AES {
	private static final String REGISTRATION_FILE = "registration.key";
	private boolean isLoggedIn = false;
	private static final String ALGORITHM = "AES";
	private static final String ENCRYPTION_KEY = "encrypttionKey";
	private JFrame frame;
	private JTextField txtUserName;
	private JPasswordField txtPassword;
	private JTextField txtTicket;
	private JTextField txtPlainText;
	private JTextField txtCipherText;
	private JButton btnEncrypt;
	private JButton btnDecrypt;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
					JRM_AES window = new JRM_AES();
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public JRM_AES() {
		initialize();
		updateButtonState();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 650, 500);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);

		JLabel lblNewLabel = new JLabel("AES Cipher Demo");
		lblNewLabel.setFont(new Font("Tahoma", Font.BOLD | Font.ITALIC, 14));
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel.setBounds(10, 10, 616, 34);
		frame.getContentPane().add(lblNewLabel);

		JLabel lblNewLabel_1 = new JLabel("User Name");
		lblNewLabel_1.setBounds(20, 74, 71, 21);
		frame.getContentPane().add(lblNewLabel_1);

		txtUserName = new JTextField();
		txtUserName.setBounds(90, 75, 516, 19);
		frame.getContentPane().add(txtUserName);
		txtUserName.setColumns(10);

		JLabel lblNewLabel_1_1 = new JLabel("Password");
		lblNewLabel_1_1.setBounds(20, 106, 71, 21);
		frame.getContentPane().add(lblNewLabel_1_1);

		txtPassword = new JPasswordField();
		txtPassword.setColumns(10);
		txtPassword.setBounds(90, 107, 516, 19);
		frame.getContentPane().add(txtPassword);

		JLabel lblNewLabel_1_1_1 = new JLabel("Ticket");
		lblNewLabel_1_1_1.setBounds(20, 137, 71, 21);
		frame.getContentPane().add(lblNewLabel_1_1_1);

		txtTicket = new JTextField();
		txtTicket.setColumns(10);
		txtTicket.setBounds(90, 138, 516, 19);
		frame.getContentPane().add(txtTicket);

		JButton btnRegister = new JButton("Register");
		btnRegister.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand().equals("Register")) {
					btn_reisterActionPerformed(e);
				}
			}
		});
		btnRegister.setBounds(36, 180, 85, 21);
		frame.getContentPane().add(btnRegister);

		JButton btnLogin = new JButton("Login");
		btnLogin.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand().equals("Login")) {
					btn_LoginActionPerformed(e);
				}
			}
		});
		btnLogin.setBounds(521, 180, 85, 21);
		frame.getContentPane().add(btnLogin);

		JLabel lblNewLabel_1_1_1_1 = new JLabel("PlainText");
		lblNewLabel_1_1_1_1.setBounds(20, 231, 71, 21);
		frame.getContentPane().add(lblNewLabel_1_1_1_1);

		txtPlainText = new JTextField();
		txtPlainText.setColumns(10);
		txtPlainText.setBounds(90, 232, 516, 83);
		frame.getContentPane().add(txtPlainText);

		JLabel lblNewLabel_1_1_1_1_1 = new JLabel("Cipher");
		lblNewLabel_1_1_1_1_1.setBounds(20, 325, 71, 21);
		frame.getContentPane().add(lblNewLabel_1_1_1_1_1);

		txtCipherText = new JTextField();
		txtCipherText.setColumns(10);
		txtCipherText.setBounds(90, 336, 516, 83);
		frame.getContentPane().add(txtCipherText);

		btnEncrypt = new JButton("Encrypt");
		btnEncrypt.setBounds(20, 429, 85, 21);
		btnEncrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand().equals("Encrypt")) {
					btn_encryptActitonPerformed(e);
				}
			}
		});
		frame.getContentPane().add(btnEncrypt);

		btnDecrypt = new JButton("Decrypt");
		btnDecrypt.setBounds(521, 432, 85, 21);
		btnDecrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand().equals("Decrypt")) {
					btn_decryptActionPerformed(e);
				}
			}
		});
		frame.getContentPane().add(btnDecrypt);
	}

	private void updateButtonState() {
		btnDecrypt.setEnabled(isLoggedIn);
		btnEncrypt.setEnabled(isLoggedIn);
	}

	public static String encrypt(String plainText, String secretKey) throws NoSuchAlgorithmException,
			InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
		SecretKey key = generateKey(secretKey);
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
		return Base64.getEncoder().encodeToString(encryptedBytes);
	}

	private static SecretKey generateKey(String secretKey) throws NoSuchAlgorithmException {
		byte[] keyBytes = secretKey.getBytes();
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ALGORITHM);
		return keySpec;
	}

	private static String decrypt(String cipherText, String secretKey) throws NoSuchAlgorithmException,
			InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
		SecretKey key = generateKey(secretKey);
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(cipher.DECRYPT_MODE, key);
		byte[] decodeBytes = Base64.getDecoder().decode(cipherText);
		byte[] decryptredBytes = cipher.doFinal(decodeBytes);
		return new String(decryptredBytes);
	}

	public static String generateRegistrationKey(String userName, String password) {
		String registrationKey = userName + ":" + password + ":" + ENCRYPTION_KEY;
		return registrationKey;
	}

	public static void saveRegistrationKeyToFile(String registratitonKey, String fileName) throws IOException {
		try (FileOutputStream fos = new FileOutputStream(fileName);
				ObjectOutputStream oos = new ObjectOutputStream(fos)) {
			oos.writeObject(registratitonKey);

		}
	}

	public static String readRegistrationKeyFromFile(String fileName) throws IOException, ClassNotFoundException {
		try (FileInputStream fis = new FileInputStream(fileName); ObjectInputStream ois = new ObjectInputStream(fis)) {
			return (String) ois.readObject();

		}
	}

	private void btn_reisterActionPerformed(ActionEvent e) {
		String username = txtUserName.getText();
		String password = txtPassword.getText();
		if (!username.isEmpty() && !password.isEmpty()) {
			try {
				String registrationKey = generateRegistrationKey(username, password);
				saveRegistrationKeyToFile(registrationKey, REGISTRATION_FILE);
				JOptionPane.showMessageDialog(frame, "Registration Successfull. Registration Key saved", "Success",
						JOptionPane.INFORMATION_MESSAGE);

			} catch (IOException ex) {
				JOptionPane.showMessageDialog(frame, "Error saving registration key: " + ex.getMessage(), "Error",
						JOptionPane.ERROR_MESSAGE);
			}
		} else {
			JOptionPane.showMessageDialog(frame, "Username and password cannot be empty", "Error",
					JOptionPane.ERROR_MESSAGE);
		}
	}

	private void btn_LoginActionPerformed(ActionEvent e) {
		String userName = txtUserName.getText();
		String password = new String(txtPassword.getPassword());
		if (!userName.isEmpty() && !password.isEmpty()) {
			try {
				String registrationKeyFromFile = readRegistrationKeyFromFile(REGISTRATION_FILE);
				String registrationKey = generateRegistrationKey(userName, password);
				if (registrationKeyFromFile.equals(registrationKey)) {
					JOptionPane.showMessageDialog(frame, "Login Successful with Registration Key: " + registrationKey,
							"Success", JOptionPane.INFORMATION_MESSAGE);
					txtTicket.setText(registrationKey);
					isLoggedIn = true;
					updateButtonState();
				} else {
					JOptionPane.showMessageDialog(frame, "Invalid UserName or password", "Error",
							JOptionPane.ERROR_MESSAGE);
				}
			} catch (IOException | ClassNotFoundException ex) {
				JOptionPane.showMessageDialog(frame, "Error reading registration key: " + ex.getMessage(), "Error",
						JOptionPane.ERROR_MESSAGE);
			}

		} else {
			JOptionPane.showMessageDialog(frame, "UserName and password cannot be empty", "Error",
					JOptionPane.ERROR_MESSAGE);
		}
	}

	private void btn_encryptActitonPerformed(ActionEvent E) {
		String plainText = txtPlainText.getText();
		String secretKey = new String(txtPassword.getPassword());
		if (!plainText.isEmpty() && !secretKey.isEmpty()) {
			try {
				String encryptedText = encrypt(plainText, secretKey);
				txtCipherText.setText(encryptedText);
			} catch (InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException
					| NoSuchAlgorithmException ex) {
				JOptionPane.showMessageDialog(frame, "Error ecrypting: " + ex.getMessage(), "Error",
						JOptionPane.ERROR_MESSAGE);
			}
		} else {
			JOptionPane.showMessageDialog(frame, "Input and secret key cannot be empty", "Error",
					JOptionPane.ERROR_MESSAGE);
		}
	}

	private void btn_decryptActionPerformed(ActionEvent e) {
		String cipherText = txtCipherText.getText();
		String secretKey = new String(txtPassword.getPassword());
		if (!cipherText.isEmpty() && !secretKey.isEmpty()) {
			try {
				String decryptedText = decrypt(cipherText, secretKey);
				txtPlainText.setText(decryptedText);
			} catch (InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException
					| NoSuchAlgorithmException ex) {
				JOptionPane.showMessageDialog(frame, "Error decrypting: " + ex.getMessage(), "Error",
						JOptionPane.ERROR_MESSAGE);
			}
		} else {
			JOptionPane.showMessageDialog(frame, "Onput and secret key cannot be empty", "Error",
					JOptionPane.ERROR_MESSAGE);
		}
	}
}
