import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class HashGenerator {

	private static int iterations = 1000;
	private static int HASH_SIZE_BITS = 16 * 8;

	public static byte[] generateStorngPasswordHash(String password, byte[] salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		char[] chars = password.toCharArray();

		PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations,
				HASH_SIZE_BITS);
		SecretKeyFactory skf = SecretKeyFactory
				.getInstance("PBKDF2WithHmacSHA1");
		byte[] hash = skf.generateSecret(spec).getEncoded();
		return hash;
	}

	//
	public static boolean validatePassword(String originalPassword,
			byte[] hash, byte[] salt) throws NoSuchAlgorithmException,
			InvalidKeySpecException {

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

	public static void main(String[] args) {

	}

}
