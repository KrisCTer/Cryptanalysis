package SSL;

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
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.awt.event.ActionEvent;

public class View_SSL extends javax.swing.JFrame {

	private JFrame frame;
	private X509Certificate generatedCertificate;
	private JTextArea txt_ComName;
	private JTextArea txt_Organ;
	private JTextArea txt_OrganUnit;
	private JTextArea txt_Locality;
	private JTextArea txt_State;
	private JTextArea txt_SSLCertificate;
	private JTextArea txt_Country;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					View_SSL window = new View_SSL();
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
	public View_SSL() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 700, 600);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);

		JButton btnGenCer = new JButton("Generate Certificate");
		btnGenCer.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Generate Certificate") {
					btn_GenerateCertificateActionPerformed(e);
				}
			}
		});
		btnGenCer.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnGenCer.setBounds(25, 501, 300, 52);
		frame.getContentPane().add(btnGenCer);

		txt_ComName = new JTextArea();
		txt_ComName.setBounds(196, 41, 480, 38);
		frame.getContentPane().add(txt_ComName);

		JLabel lblNewLabel_3_1 = new JLabel("Common Name (CN)");
		lblNewLabel_3_1.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_3_1.setBounds(10, 41, 176, 38);
		frame.getContentPane().add(lblNewLabel_3_1);

		JLabel Elliptic = new JLabel("SSL Certificate Generate (SHA-256 & RSA)");
		Elliptic.setHorizontalAlignment(SwingConstants.CENTER);
		Elliptic.setFont(new Font("Tahoma", Font.BOLD, 20));
		Elliptic.setBounds(10, 0, 666, 38);
		frame.getContentPane().add(Elliptic);

		txt_Organ = new JTextArea();
		txt_Organ.setBounds(196, 89, 480, 38);
		frame.getContentPane().add(txt_Organ);

		JLabel lblNewLabel_3_1_1 = new JLabel("Organization (O)");
		lblNewLabel_3_1_1.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_3_1_1.setBounds(10, 89, 176, 38);
		frame.getContentPane().add(lblNewLabel_3_1_1);

		txt_OrganUnit = new JTextArea();
		txt_OrganUnit.setBounds(196, 137, 480, 38);
		frame.getContentPane().add(txt_OrganUnit);

		JLabel lblNewLabel_3_1_2 = new JLabel("Organizational Unit (OU)");
		lblNewLabel_3_1_2.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_3_1_2.setBounds(10, 137, 176, 38);
		frame.getContentPane().add(lblNewLabel_3_1_2);

		txt_Locality = new JTextArea();
		txt_Locality.setBounds(196, 185, 480, 38);
		frame.getContentPane().add(txt_Locality);

		JLabel lblNewLabel_3_1_3 = new JLabel("Locality (L)");
		lblNewLabel_3_1_3.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_3_1_3.setBounds(10, 185, 176, 38);
		frame.getContentPane().add(lblNewLabel_3_1_3);

		txt_State = new JTextArea();
		txt_State.setBounds(196, 233, 480, 38);
		frame.getContentPane().add(txt_State);

		JLabel lblNewLabel_3_1_4 = new JLabel("State (ST)");
		lblNewLabel_3_1_4.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_3_1_4.setBounds(10, 233, 176, 38);
		frame.getContentPane().add(lblNewLabel_3_1_4);

		txt_Country = new JTextArea();
		txt_Country.setBounds(196, 281, 480, 38);
		frame.getContentPane().add(txt_Country);

		JLabel lblNewLabel_3_1_5 = new JLabel("Country (C)");
		lblNewLabel_3_1_5.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_3_1_5.setBounds(10, 281, 176, 38);
		frame.getContentPane().add(lblNewLabel_3_1_5);

		txt_SSLCertificate = new JTextArea();
		txt_SSLCertificate.setBounds(196, 329, 480, 150);
		frame.getContentPane().add(txt_SSLCertificate);

		JLabel lblNewLabel_3_1_6 = new JLabel("SSL Certificate");
		lblNewLabel_3_1_6.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_3_1_6.setBounds(10, 329, 176, 150);
		frame.getContentPane().add(lblNewLabel_3_1_6);

		JButton btnSaveSer = new JButton("Save Sertificate");
		btnSaveSer.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getActionCommand() == "Save Sertificate") {
					btn_SaveSertificateActionPerformed(e);
				}
			}
		});
		btnSaveSer.setFont(new Font("Tahoma", Font.PLAIN, 15));
		btnSaveSer.setBounds(365, 501, 300, 52);
		frame.getContentPane().add(btnSaveSer);
	}

	protected void btn_SaveSertificateActionPerformed(ActionEvent e) {
		if (this.generatedCertificate == null) {
			JOptionPane.showMessageDialog(this.frame, "No certificate to save. Please generate a certificate first.",
					"Error", JOptionPane.ERROR_MESSAGE);
			return;
		}
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setDialogTitle("Save Certificate as PEM");
		int userSelection = fileChooser.showSaveDialog(this.frame);
		if (userSelection == JFileChooser.APPROVE_OPTION) {
			File fileToSave = fileChooser.getSelectedFile();
			if (!fileToSave.getAbsolutePath().endsWith(".pem")) {
				fileToSave = new File(fileToSave + ".pem");
			}
			try (FileWriter writer = new FileWriter(fileToSave)) {
				String pemCertificate = SSLUtil.convertToPEM(generatedCertificate);
				writer.write(pemCertificate);
				JOptionPane.showMessageDialog(this.frame, "Certificate saved successfullt.", "Success",
						JOptionPane.INFORMATION_MESSAGE);
			} catch (IOException ex) {
				JOptionPane.showMessageDialog(this.frame, "Error saving certificate: " + ex.getMessage(), "Error",
						JOptionPane.ERROR_MESSAGE);
			} catch (Exception ex) {
				Logger.getLogger(View_SSL.class.getName()).log(Level.SEVERE, null, ex);
			}
		}
	}

	protected void btn_GenerateCertificateActionPerformed(ActionEvent e) {
		generatedCertificate();
	}

	private void generatedCertificate() {
		try {
			String dn = "CN=" + this.txt_ComName.getText() + ", O=" + this.txt_Organ.getText() + ", OU="
					+ this.txt_OrganUnit.getText() + ", L=" + this.txt_Locality.getText() + ", ST="
					+ this.txt_State.getText() + ", C=" + this.txt_Country.getText();
			KeyPair keyPair = SSLUtil.generateRSAKeyPair();
			this.generatedCertificate = SSLUtil.generateSelfSignedCertificate(keyPair, dn);
			this.txt_SSLCertificate.setText(this.generatedCertificate.toString());
		} catch (Exception e) {
			JOptionPane.showMessageDialog(this.frame, "Error generating certificate: " + e.getMessage(), "Error",
					JOptionPane.ERROR_MESSAGE);
		}

	}

}
