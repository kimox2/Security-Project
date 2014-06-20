import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Test {
	public static void main(String[] args) throws NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchPaddingException, UnsupportedEncodingException,
			NoSuchProviderException, InvalidAlgorithmParameterException {

		String originalPassword = "password";
		// get hash from the user password
		byte[] salt = getSalt().getBytes();
		byte[] hash = generateStorngPasswordHash(originalPassword, salt);
		String generatedSecuredPasswordHash = 1000 + ":" + toHex(salt) + ":"
				+ toHex(hash);
		System.out.println("numof iter.:salt:hash ="
				+ generatedSecuredPasswordHash);

		// It must return true
		boolean matched = validatePassword("password",
				generatedSecuredPasswordHash);
		System.out.println(matched);
		// return false as other user password
		matched = validatePassword("password1", generatedSecuredPasswordHash);
		System.out.println(matched);

		// encrypt string based on the hash of the user password and using the
		// hash as key
		byte[] cipher = encrypt("kalo", hash);
		System.out.println(dcrypt(cipher, hash));
		
		
		byte []tt=EncryptionDecryptionWrapper.encryptHmac("www.f.com", hash);
		System.out.println(EncryptionDecryptionWrapper.validate("www.f.com", toHex(tt), hash));
	}

	private static byte[] encrypt(String message, byte[] hash)
			throws IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, UnsupportedEncodingException,
			NoSuchProviderException, InvalidAlgorithmParameterException {

		SecretKeySpec skeySpec = new SecretKeySpec(hash, "AES");
		GCMParameterSpec s = new GCMParameterSpec(128, hash);
		// Get a cipher object.
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, s);
		// Gets the raw bytes to encrypt, UTF8 is needed for
		// having a standard character set
		byte[] stringBytes = message.getBytes("UTF8");
		// encrypt using the cypher
		byte[] raw = cipher.doFinal(stringBytes);
		System.out.println(raw.length);
		return raw;
	}

	private static String dcrypt(byte[] password, byte[] hash)
			throws IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, UnsupportedEncodingException,
			NoSuchProviderException, InvalidAlgorithmParameterException {

		SecretKeySpec skeySpec = new SecretKeySpec(hash, "AES");
		GCMParameterSpec s = new GCMParameterSpec(128, hash);
		// Get a cipher object.
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, s);
		// encrypt using the cypher
		byte[] raw = cipher.doFinal(password);
		return new String(raw);
	}

	private static byte[] generateStorngPasswordHash(String password,
			byte[] salt) throws NoSuchAlgorithmException,
			InvalidKeySpecException {
		int iterations = 1000;
		char[] chars = password.toCharArray();

		PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 128);
		SecretKeyFactory skf = SecretKeyFactory
				.getInstance("PBKDF2WithHmacSHA1");
		byte[] hash = skf.generateSecret(spec).getEncoded();
		return hash;
	}

	private static String getSalt() throws NoSuchAlgorithmException {
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		byte[] salt = new byte[16];
		sr.nextBytes(salt);
		return salt.toString();
	}

	private static String toHex(byte[] array) throws NoSuchAlgorithmException {
		BigInteger bi = new BigInteger(1, array);
		String hex = bi.toString(16);
		int paddingLength = (array.length * 2) - hex.length();
		if (paddingLength > 0) {
			return String.format("%0" + paddingLength + "d", 0) + hex;
		} else {
			return hex;
		}
	}

	private static boolean validatePassword(String originalPassword,
			String storedPassword) throws NoSuchAlgorithmException,
			InvalidKeySpecException {
		String[] parts = storedPassword.split(":");
		int iterations = Integer.parseInt(parts[0]);
		byte[] salt = fromHex(parts[1]);
		byte[] hash = fromHex(parts[2]);
		PBEKeySpec spec = new PBEKeySpec(originalPassword.toCharArray(), salt,
				iterations, hash.length * 8);
		SecretKeyFactory skf = SecretKeyFactory
				.getInstance("PBKDF2WithHmacSHA1");
		byte[] testHash = skf.generateSecret(spec).getEncoded();

		int diff = hash.length ^ testHash.length;
		for (int i = 0; i < hash.length && i < testHash.length; i++) {
			diff |= hash[i] ^ testHash[i];
		}
		return diff == 0;
	}

	private static byte[] fromHex(String hex) throws NoSuchAlgorithmException {
		byte[] bytes = new byte[hex.length() / 2];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2),
					16);
		}
		return bytes;
	}
}