package Test3;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class RSAEncryptDecrypt {
	private static String fileBase = "server";
	
	public static void main(String[] args) throws Exception {
		
		// generate public (server.pub) and privateKey (server.key)
		// comment below method if you want to use already generated one.
		generatePublicPrivateKey();
		
		KeyFactory kf = KeyFactory.getInstance("RSA");

		byte[] publicKeyBytes = Files.readAllBytes(Paths.get(fileBase + ".pub"));
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
		PublicKey pub = kf.generatePublic(x509EncodedKeySpec);

		byte[] privateKeyBytes = Files.readAllBytes(Paths.get(fileBase + ".key"));
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privateKeyBytes);
		PrivateKey pvt = kf.generatePrivate(ks);

		// Encrypting a File Using the Private Key
		File inputFile = new File("data.txt");
		File encryptedFile = new File("data-enc.txt");
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, pvt);
		try (FileInputStream in = new FileInputStream(inputFile); FileOutputStream out = new FileOutputStream(encryptedFile)) {
			processFile(cipher, in, out);
		}

		// Decrypting an Encrypted File
		File verifyFile = new File("data-ver.txt");
		cipher.init(Cipher.DECRYPT_MODE, pub);
		try (FileInputStream in = new FileInputStream(encryptedFile);
		     FileOutputStream out = new FileOutputStream(verifyFile)) {
		    processFile(cipher, in, out);
		}
	}
	
	private static void generatePublicPrivateKey() throws NoSuchAlgorithmException, FileNotFoundException, IOException {
		// Generating Public and Private Keys

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();

		// Saving and Restoring Keys
		try (FileOutputStream out = new FileOutputStream(fileBase + ".key")) {
			out.write(kp.getPrivate().getEncoded());
		}

		try (FileOutputStream out = new FileOutputStream(fileBase + ".pub")) {
			out.write(kp.getPublic().getEncoded());
		}
	}
	
	private static void processFile(Cipher ci, InputStream in, OutputStream out)
			throws IOException, IllegalBlockSizeException, BadPaddingException {
		byte[] ibuf = new byte[1024];
		int len;
		while ((len = in.read(ibuf)) != -1) {
			byte[] obuf = ci.update(ibuf, 0, len);
			if (obuf != null)
				out.write(obuf);
		}
		byte[] obuf = ci.doFinal();
		if (obuf != null)
			out.write(obuf);
	}
}
