package Transposition;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JButton;
import javax.swing.JFileChooser;

import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.Arrays;
import java.awt.event.ActionEvent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.UIManager;
import javax.swing.filechooser.FileNameExtensionFilter;

import java.awt.Font;
import javax.swing.SwingConstants;

public class View_Transposition {

	private JFrame frame;
	private JTextField plainText;
	private JTextField key;
	private JTextField cipherText;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					View_Transposition window = new View_Transposition();
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
	public View_Transposition() {
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
		Decrypt.setBounds(141, 205, 85, 21);
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
		btnNewButton_2.setBounds(236, 205, 163, 21);
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
		lblNewLabel_2.setBounds(10, 148, 59, 13);
		frame.getContentPane().add(lblNewLabel_2);

		plainText = new JTextField();
		plainText.setBounds(79, 44, 320, 46);
		frame.getContentPane().add(plainText);
		plainText.setColumns(10);

		key = new JTextField();
		key.setColumns(10);
		key.setBounds(79, 100, 320, 19);
		frame.getContentPane().add(key);

		cipherText = new JTextField();
		cipherText.setColumns(10);
		cipherText.setBounds(79, 134, 320, 41);
		frame.getContentPane().add(cipherText);

		JLabel lblNewLabel = new JLabel("Transposition");
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel.setFont(new Font("Tahoma", Font.BOLD, 16));
		lblNewLabel.setBounds(10, 10, 413, 24);
		frame.getContentPane().add(lblNewLabel);
	}

	private void btn_encryptActionPerformed(ActionEvent evt) {
		try {
			String plaintext = this.plainText.getText();
			String keyStr = this.key.getText();

			int[] arrKey = Arrays.stream(keyStr.split(",")).mapToInt(Integer::parseInt).toArray();
			String ct = TranspositionCipher.encrypt(plaintext, arrKey);
			JOptionPane.showMessageDialog(this.frame, "Encrypt successfully");
			cipherText.setText(ct);
			this.saveToFile(ct);
		} catch (Exception e) {
			JOptionPane.showMessageDialog(this.frame, "Math Error");
		}
	}

	private void btn_decryptActionPerformed(ActionEvent evt) {
		try {
			String cipherText = this.cipherText.getText();
			String keyStr = this.key.getText();

			int[] arrKey = Arrays.stream(keyStr.split(",")).mapToInt(Integer::parseInt).toArray();
			String ct = TranspositionCipher.decrypt(cipherText, arrKey);
			JOptionPane.showMessageDialog(this.frame, "Decrypt successfully");
			plainText.setText(ct);
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
