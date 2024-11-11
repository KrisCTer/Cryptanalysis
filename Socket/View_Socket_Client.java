package Socket;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JLabel;
import java.awt.Font;
import java.awt.JobAttributes.SidesType;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import org.bouncycastle.crypto.io.CipherIOException;

import javax.swing.JTextArea;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.ldap.SortResponseControl;
import javax.swing.JButton;

public class View_Socket_Client {

	private JFrame frame;
	private JButton btnConnect;
	private JTextArea txt_Port;
	private JLabel lblStatus;
	private JTextArea txt_EnterText;

	private Socket socket;
	private ObjectOutputStream out;
	private ObjectInputStream in;
	private KeyAgreement keyAgreement;
	private SecretKey secretKey;
	private JTextArea txt_IP;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
					View_Socket_Client window = new View_Socket_Client();
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
	public View_Socket_Client() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 450, 430);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);

		JLabel lblNewLabel = new JLabel("Diffie-Hellman key exchange with Socket - Client");
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel.setFont(new Font("Tahoma", Font.BOLD, 15));
		lblNewLabel.setBounds(10, 10, 416, 31);
		frame.getContentPane().add(lblNewLabel);

		txt_IP = new JTextArea();
		txt_IP.setBounds(120, 51, 306, 22);
		frame.getContentPane().add(txt_IP);

		txt_Port = new JTextArea();
		txt_Port.setBounds(120, 83, 306, 22);
		frame.getContentPane().add(txt_Port);

		JLabel lblNewLabel_1 = new JLabel("IP Address");
		lblNewLabel_1.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_1.setBounds(10, 51, 100, 22);
		frame.getContentPane().add(lblNewLabel_1);

		JLabel lblNewLabel_1_1 = new JLabel("Port");
		lblNewLabel_1_1.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_1_1.setBounds(10, 83, 100, 22);
		frame.getContentPane().add(lblNewLabel_1_1);

		btnConnect = new JButton("Connect");
		btnConnect.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Connect") {
					btnConnectActionPerformed(e);
				}
			}
		});
		btnConnect.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnConnect.setBounds(10, 115, 100, 54);
		frame.getContentPane().add(btnConnect);

		lblStatus = new JLabel("");
		lblStatus.setFont(new Font("Tahoma", Font.PLAIN, 13));
		lblStatus.setBounds(120, 115, 306, 54);
		frame.getContentPane().add(lblStatus);

		JLabel lblNewLabel_1_2 = new JLabel("Enter text");
		lblNewLabel_1_2.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_1_2.setBounds(10, 179, 416, 22);
		frame.getContentPane().add(lblNewLabel_1_2);

		txt_EnterText = new JTextArea();
		txt_EnterText.setBounds(10, 211, 416, 100);
		frame.getContentPane().add(txt_EnterText);

		JButton btnSendToServer = new JButton("Send to Server");
		btnSendToServer.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Send to Server") {
					btn_SendToServerActionPerformed(e);
				}
			}
		});
		btnSendToServer.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnSendToServer.setBounds(10, 321, 200, 54);
		frame.getContentPane().add(btnSendToServer);

		JButton btnDisonnect = new JButton("Disconnect");
		btnDisonnect.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Disconnect") {
					btn_DisconnectActionPerformed(e);
				}
			}
		});
		btnDisonnect.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnDisonnect.setBounds(226, 321, 200, 54);
		frame.getContentPane().add(btnDisonnect);
	}

	protected void btn_DisconnectActionPerformed(ActionEvent e) {
		try {
			if (this.socket != null && !this.socket.isClosed()) {
				this.socket.close();
				this.lblStatus.setText("Status: Disconnected from server.");
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			this.lblStatus.setText("Status: Error Disconnected.");
		}

	}

	protected void btn_SendToServerActionPerformed(ActionEvent e) {
		try {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, this.secretKey);
			byte[] encryptedBytes = cipher.doFinal(this.txt_EnterText.getText().getBytes());

			this.out.writeObject(encryptedBytes);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException | IOException ex) {
			ex.printStackTrace();
			this.lblStatus.setText("Status: Error Sending Message.");
		}

	}

	protected void btnConnectActionPerformed(ActionEvent e) {
		try {
			this.socket = new Socket(this.txt_IP.getText(), Integer.parseInt(this.txt_Port.getText()));
			out = new ObjectOutputStream(this.socket.getOutputStream());
			in = new ObjectInputStream(this.socket.getInputStream());

			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DiffieHellman");
			keyPairGenerator.initialize(1024);
			KeyPair clientKeyPair = keyPairGenerator.generateKeyPair();
			this.keyAgreement = KeyAgreement.getInstance("DiffieHellman");
			this.keyAgreement.init(clientKeyPair.getPrivate());

			out.writeObject(clientKeyPair.getPublic().getEncoded());

			byte[] serverPublicKeyBytes = (byte[]) in.readObject();
			KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(serverPublicKeyBytes);
			PublicKey serverPublicKey = keyFactory.generatePublic(x509EncodedKeySpec);

			this.keyAgreement.doPhase(serverPublicKey, true);

			byte[] sharedSecret = this.keyAgreement.generateSecret();
			this.secretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

			this.lblStatus.setText("Status: Connected to server.");

		} catch (IOException | NoSuchAlgorithmException | InvalidKeyException | ClassNotFoundException
				| InvalidKeySpecException ex) {
			ex.printStackTrace();
			this.lblStatus.setText("Status: Connected failed.");
		}
	}
}
