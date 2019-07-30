import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES logic to encrypt decrypt and generate key.
 * 
 * @author bibhuti_agarwal
 * @version 1.0
 */
public class AESEncryptionDecryption {

	private static SecretKeySpec secretKey;
	private static byte[] key;
	
	/**
	 * @param secret holds the secret key to encrypt or decrypt 
	 */
	private static void setKey(String secret) {
		MessageDigest sha = null;
		try {
			key = secret.getBytes("UTF-8");
			sha = MessageDigest.getInstance("SHA-256");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
			secretKey = new SecretKeySpec(key, "AES");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * 
	 * @param encryptString raw string to encrypt
	 * @param secret holds the secret key to encrypt or decrypt 
	 * @return encrypted string
	 */
	public static String encrypt(String encryptString, String secret) {
			setKey(secret);
			Cipher cipher = null;
			try {
				cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
				cipher.init(Cipher.ENCRYPT_MODE, secretKey);
				return Base64.getEncoder().encodeToString(cipher.doFinal(encryptString.getBytes("UTF-8")));
			} catch (IllegalBlockSizeException | BadPaddingException e) {
				throw new RuntimeException("Illegal Block Size or Bad Padding Exception", e);
			} catch (UnsupportedEncodingException e) {
				throw new RuntimeException("Unsupported Encoding Exception", e);
			} catch (InvalidKeyException e) {
				throw new RuntimeException("Invalid Key Exception", e);
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				throw new RuntimeException("No Such Algorithm or Padding Exception" , e);
			}
	}

	/**
	 * 
	 * @param decryptString encrypted string to decrypt
	 * @param secret holds the secret key to encrypt or decrypt 
	 * @return decrypted string
	 */
	public static String decrypt(String decryptString, String secret) {
			setKey(secret);
			Cipher cipher;
			try {
				cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
				cipher.init(Cipher.DECRYPT_MODE, secretKey);
				return new String(cipher.doFinal(Base64.getDecoder().decode(decryptString)));
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				throw new RuntimeException("No Such Algorithm or Padding Exception" , e);
			} catch (InvalidKeyException e) {
				throw new RuntimeException("Invalid Key Exception", e);
			} catch (IllegalBlockSizeException | BadPaddingException e) {
				throw new RuntimeException("Illegal Block Size or Bad Padding Exception", e);
			}
	}

	/**
	 * @return generates random key which can be used as secret key for 
	 * encryption or decryption.
	 */
	public static String generateKey() {
		KeyGenerator keyGen;
		try {
			keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			SecretKey secretKey = keyGen.generateKey();
			return Base64.getEncoder().encodeToString(secretKey.getEncoded());
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("No Such Algorithm Exception" , e);
		}
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException {
		final String secretKey = "Fb2bhzEkys0yi28CI0gsew==";//AES.generateKey();
		
		String originalString = "cxcxzzczxcxzczxczxc";
		String encryptedString = AES.encrypt(originalString, secretKey);
		String decryptedString = AES.decrypt(encryptedString, secretKey);

		System.out.println("Secret Key :" + secretKey);
		System.out.println("Encrypted String : " + encryptedString);
		System.out.println("Decrypted String : " + decryptedString);
	}
}
