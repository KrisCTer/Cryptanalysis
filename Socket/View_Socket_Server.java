package Socket;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JLabel;
import java.awt.Font;
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
import javax.swing.JTextArea;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;

public class View_Socket_Server {

	private JFrame frame;
	private JButton btnConnect;
	private JTextArea txt_Port;
	private JLabel lblStatus;
	private JTextArea txt_Received;
	private JTextArea txt_Decrypted;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
					View_Socket_Server window = new View_Socket_Server();
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
	public View_Socket_Server() {
		initialize();
		this.btnConnect.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				new Thread(() -> startServer()).start();

			}
		});
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 450, 500);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);

		JLabel lblNewLabel = new JLabel("Diffie-Hellman key exchange with Socket - Server");
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel.setFont(new Font("Tahoma", Font.BOLD, 15));
		lblNewLabel.setBounds(10, 10, 416, 31);
		frame.getContentPane().add(lblNewLabel);

		JTextArea txt_IP = new JTextArea();
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
		btnConnect.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnConnect.setBounds(10, 115, 100, 54);
		frame.getContentPane().add(btnConnect);

		lblStatus = new JLabel("");
		lblStatus.setFont(new Font("Tahoma", Font.PLAIN, 13));
		lblStatus.setBounds(120, 115, 306, 54);
		frame.getContentPane().add(lblStatus);

		JLabel lblNewLabel_1_2 = new JLabel("Received message from client:");
		lblNewLabel_1_2.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_1_2.setBounds(10, 179, 416, 22);
		frame.getContentPane().add(lblNewLabel_1_2);

		txt_Received = new JTextArea();
		txt_Received.setBounds(10, 211, 416, 100);
		frame.getContentPane().add(txt_Received);

		JLabel lblNewLabel_1_2_1 = new JLabel("Decrypted message from client:");
		lblNewLabel_1_2_1.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_1_2_1.setBounds(10, 321, 416, 22);
		frame.getContentPane().add(lblNewLabel_1_2_1);

		txt_Decrypted = new JTextArea();
		txt_Decrypted.setBounds(10, 353, 416, 100);
		frame.getContentPane().add(txt_Decrypted);
	}

	private void startServer() {
		try {
			int port = Integer.parseInt(this.txt_Port.getText());
			try (ServerSocket serverSocket = new ServerSocket(port)) {
				SwingUtilities.invokeLater(() -> this.lblStatus.setText("Status: Waiting for client..."));
				Socket socket = serverSocket.accept();
				SwingUtilities.invokeLater(() -> this.lblStatus.setText("Status: Client connected."));

				KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DiffieHellman");
				keyPairGen.initialize(1024);
				KeyPair serverKeyPair = keyPairGen.generateKeyPair();
				KeyAgreement serverKeyAgreement = KeyAgreement.getInstance("DiffieHellman");
				serverKeyAgreement.init(serverKeyPair.getPrivate());

				ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
				out.writeObject(serverKeyPair.getPublic().getEncoded());

				ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
				byte[] clientPublicKeyBytes = (byte[]) in.readObject();
				KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
				X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(clientPublicKeyBytes);
				PublicKey clientPublicKey = keyFactory.generatePublic(x509EncodedKeySpec);

				serverKeyAgreement.doPhase(clientPublicKey, true);

				byte[] sharedBytes = serverKeyAgreement.generateSecret();
				SecretKeySpec secretKeySpec = new SecretKeySpec(sharedBytes, 0, 16, "AES");

				byte[] encryptedBytes = (byte[]) in.readObject();
				Cipher cipher = Cipher.getInstance("AES");
				cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
				String decryptedMessage = new String(cipher.doFinal(encryptedBytes));
				SwingUtilities.invokeLater(() -> {
					this.txt_Received.setText(new String(encryptedBytes));
					this.txt_Decrypted.setText(decryptedMessage);
				});
				socket.close();
				SwingUtilities.invokeLater(() -> this.lblStatus.setText("Status: Client is disconeccted!"));
			}
		} catch (IOException | NoSuchAlgorithmException | InvalidKeyException | ClassNotFoundException
				| NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException
				| InvalidKeySpecException e) {
			e.printStackTrace();
			SwingUtilities.invokeLater(() -> this.lblStatus.setText("Status: Error occurred!"));
		}
	}
}
