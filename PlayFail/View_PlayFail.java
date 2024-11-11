package PlayFail;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JButton;
import javax.swing.JFileChooser;

import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.awt.event.ActionEvent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.UIManager;
import javax.swing.filechooser.FileNameExtensionFilter;

import java.awt.Font;
import javax.swing.SwingConstants;
import javax.swing.JTextArea;
import javax.swing.JPasswordField;

public class View_PlayFail {

	private JFrame frame;
	private JTextField plainText;
	private JTextField key;
	private JTextField cipherText;
	private PlayFailCipher playFailCipher;
	private JTextArea matrix;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					View_PlayFail window = new View_PlayFail();
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
	public View_PlayFail() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 570, 380);
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
		Encrypt.setBounds(192, 301, 85, 21);
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
		Decrypt.setBounds(287, 301, 85, 21);
		frame.getContentPane().add(Decrypt);

		JButton btnNewButton_2 = new JButton("Open Ciphertext file");
		btnNewButton_2.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Open Ciphertext file") {
					btn_openfileActionPerformed(e);
				}
			}
		});
		btnNewButton_2.setFont(new Font("Tahoma", Font.PLAIN, 13));
		btnNewButton_2.setBounds(382, 301, 164, 21);
		frame.getContentPane().add(btnNewButton_2);

		JLabel plaintext = new JLabel("Plain Text");
		plaintext.setFont(new Font("Tahoma", Font.PLAIN, 13));
		plaintext.setBounds(10, 60, 59, 13);
		frame.getContentPane().add(plaintext);

		JLabel lblNewLabel_1 = new JLabel("Key");
		lblNewLabel_1.setFont(new Font("Tahoma", Font.PLAIN, 13));
		lblNewLabel_1.setBounds(10, 103, 59, 13);
		frame.getContentPane().add(lblNewLabel_1);

		JLabel lblNewLabel_2 = new JLabel("Ciphertext");
		lblNewLabel_2.setFont(new Font("Tahoma", Font.PLAIN, 13));
		lblNewLabel_2.setBounds(10, 264, 59, 13);
		frame.getContentPane().add(lblNewLabel_2);

		plainText = new JTextField();
		plainText.setBounds(79, 44, 467, 46);
		frame.getContentPane().add(plainText);
		plainText.setColumns(10);

		key = new JTextField();
		key.setColumns(10);
		key.setBounds(79, 100, 467, 19);
		frame.getContentPane().add(key);

		cipherText = new JTextField();
		cipherText.setColumns(10);
		cipherText.setBounds(79, 250, 467, 41);
		frame.getContentPane().add(cipherText);

		JLabel lblNewLabel = new JLabel("PlayFail");
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel.setFont(new Font("Tahoma", Font.BOLD, 16));
		lblNewLabel.setBounds(0, 10, 556, 24);
		frame.getContentPane().add(lblNewLabel);

		JButton keyMatrix = new JButton("Generate Key Matrix");
		keyMatrix.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Generate Key Matrix") {
					btn_generateKeyMatrix(e);
				}
			}
		});
		keyMatrix.setFont(new Font("Tahoma", Font.PLAIN, 13));
		keyMatrix.setBounds(10, 302, 172, 21);
		frame.getContentPane().add(keyMatrix);

		JLabel lblNewLabel_2_1 = new JLabel("Key Matrix");
		lblNewLabel_2_1.setFont(new Font("Tahoma", Font.PLAIN, 13));
		lblNewLabel_2_1.setBounds(10, 140, 59, 100);
		frame.getContentPane().add(lblNewLabel_2_1);

		matrix = new JTextArea();
		matrix.setEditable(false);
		matrix.setBounds(79, 129, 467, 111);
		frame.getContentPane().add(matrix);
	}

	private void btn_generateKeyMatrix(ActionEvent e) {
		String key = this.key.getText();
		if (!key.isEmpty()) {
			playFailCipher = new PlayFailCipher(key);
			String keyMatrixString = playFailCipher.getKeyMatrixAsString();
			matrix.setText(keyMatrixString);

		} else
			JOptionPane.showMessageDialog(this.frame, "Math Error");
	}

	private void btn_encryptActionPerformed(ActionEvent evt) {
		try {
			String plaintext = this.plainText.getText();
			String key = this.key.getText();

			if (!plaintext.isEmpty() && !key.isEmpty()) {
				playFailCipher = new PlayFailCipher(key);
				String ct = PlayFailCipher.encript(plaintext);
				JOptionPane.showMessageDialog(this.frame, "Encrypt successfully");
				cipherText.setText(ct);
				this.saveToFile(ct);
			}
		} catch (Exception e) {
			JOptionPane.showMessageDialog(this.frame, "Math Error");
		}
	}

	private void btn_decryptActionPerformed(ActionEvent evt) {
		try {
			String ciphertextToDe = this.cipherText.getText();
			String key = this.key.getText();
			if (!ciphertextToDe.isEmpty() && !key.isEmpty()) {
				playFailCipher = new PlayFailCipher(key);
				String ct = PlayFailCipher.decript(ciphertextToDe);
				JOptionPane.showMessageDialog(this.frame, "Decrypt successfully");
				plainText.setText(ct);
			}
		} catch (Exception e) {
			JOptionPane.showMessageDialog(this.frame, "Math Error");
		}
	}

	private void btn_openfileActionPerformed(ActionEvent evt) {
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setFileFilter(new FileNameExtensionFilter("Text file", "txt"));

		int userSelection = fileChooser.showOpenDialog(this.frame);
		if (userSelection == JFileChooser.APPROVE_OPTION) {
			try (BufferedReader br = new BufferedReader(new FileReader(fileChooser.getSelectedFile()))) {
				JOptionPane.showMessageDialog(this.frame, "File Open successfully");
				cipherText.read(br, null);
			} catch (Exception e) {
				JOptionPane.showMessageDialog(this.frame, "Error opening file: " + e.getMessage());
			}
		}
	}

	private void saveToFile(String content) {
		JFileChooser fc = new JFileChooser();
		FileNameExtensionFilter filter = new FileNameExtensionFilter("Text Files", "txt");
		fc.setFileFilter(filter);
		int userSelection = fc.showSaveDialog(this.frame);
		if (userSelection == JFileChooser.APPROVE_OPTION) {
			try (FileWriter fw = new FileWriter(fc.getSelectedFile() + ".txt")) {
				JOptionPane.showMessageDialog(this.frame, "File saved successfully");
				fw.write(content);
			} catch (Exception e) {
				JOptionPane.showMessageDialog(this.frame, "Error saving file: " + e.getMessage());
			}
		}
	}
}
