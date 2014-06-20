import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionDecryptionWrapper {

	public static String encrypt(String message, byte[] hash)
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


		/*cipher.init(Cipher.DECRYPT_MODE, skeySpec, s);
		byte[] text = cipher.doFinal(raw);*/
		
		return new String(raw);

	}
	
	public static String toHex(byte[] array) throws NoSuchAlgorithmException {
		BigInteger bi = new BigInteger(1, array);
		String hex = bi.toString(16);
		int paddingLength = (array.length * 2) - hex.length();
		if (paddingLength > 0) {
			return String.format("%0" + paddingLength + "d", 0) + hex;
		} else {
			return hex;
		}
	}
	
	public static String decrypt(String cryptedMessage, byte[] hash)
	{
		try{
			SecretKeySpec skeySpec = new SecretKeySpec(hash, "AES");
			GCMParameterSpec s = new GCMParameterSpec(128, hash);
			// Get a cipher object.
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, s);
	
			// Gets the raw bytes to encrypt, UTF8 is needed for
			// having a standard character set
			byte[] stringBytes = cryptedMessage.getBytes();
			// encrypt using the cypher
			byte[] raw = cipher.doFinal(stringBytes);
			
			return new String(raw);
		}catch(Exception e){
			e.printStackTrace();
			return null;
		}
	}
	
	public static byte[] encryptHmac(String domainName,byte[] hash) throws InvalidKeyException, NoSuchAlgorithmException{
		  SecretKeySpec signingKey = new SecretKeySpec(hash, "HmacSHA1");
		  Mac mac = Mac.getInstance("HmacSHA1");
		  mac.init(signingKey);
		  return (mac.doFinal(domainName.getBytes()));
		 }

}
