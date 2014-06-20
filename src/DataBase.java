import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class DataBase {

	private static byte[] salt;
	private Table table;
	private HashMap<String, Table> users = new HashMap<String, Table>();
	

	public DataBase() throws NoSuchAlgorithmException, IOException {
		File f = new File("params.txt");
		if (f.exists()) {
			BufferedReader reader = new BufferedReader(new FileReader(f));
			salt = reader.readLine().getBytes();
			reader.close();
		} else {
			BufferedWriter writer = new BufferedWriter(new FileWriter(f));
			String temp = getSalt();
			writer.write(temp);
			writer.close();
			salt = temp.getBytes();
		}
		table = new Table();

	}

	private void saveTables() {
		try {

			FileOutputStream fout = new FileOutputStream("users.txt");
			ObjectOutputStream oos = new ObjectOutputStream(fout);
			oos.writeObject(users);
			oos.close();

			fout = new FileOutputStream("table.txt");
			oos = new ObjectOutputStream(fout);
			oos.writeObject(table);
			oos.close();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	private void loadTables() {

		try {
			// load users
			File f = new File("users.txt");
			FileInputStream streamIn = new FileInputStream(f);
			ObjectInputStream objectinputstream = new ObjectInputStream(
					streamIn);
			users = (HashMap<String, Table>) objectinputstream.readObject();
			objectinputstream.close();
			// load table
			streamIn = new FileInputStream("table.txt");
			objectinputstream = new ObjectInputStream(streamIn);
			table = (Table) objectinputstream.readObject();
			objectinputstream.close();
		} catch (Exception e) {

			// e.printStackTrace();
		}
	}

	private static String getSalt() throws NoSuchAlgorithmException {
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		byte[] salt = new byte[16];
		sr.nextBytes(salt);
		return new String(salt);
	}

	private byte[] authUser(String password) throws NoSuchAlgorithmException,
			InvalidKeySpecException {
		byte[] hash = HashGenerator.generateStorngPasswordHash(password, salt);
		return hash;
	}

	private Table validatePassword(String password)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		for (Map.Entry<String, Table> e : users.entrySet()) {
			byte[] hash = fromHex(e.getKey());
			if (HashGenerator.validatePassword(password, hash, salt)) {
				System.out.println(e.getKey());
				return e.getValue();
			}
		}
		return null;
	}

	private String passwordPadding(String password) {
		if (password.length() >= 16)
			return password;

		while (password.length() < 16)
			password += "$";

		return password;
	}

	private byte[] getHash(String password) throws NoSuchAlgorithmException,
			InvalidKeySpecException {
		for (Map.Entry<String, Table> e : users.entrySet()) {
			byte[] hash = fromHex(e.getKey());
			if (HashGenerator.validatePassword(password, hash, salt)) {
				// System.out.println(e.getKey());
				return hash;
			}
		}
		return null;
	}

	public void addUser(byte[] hash) throws NoSuchAlgorithmException {
		String sh = toHex(hash);
		table = new Table();
		users.put(sh, table);
	}

	public void userStart(byte[] userHash) {
		while (true) {
			try {
				BufferedReader reader = new BufferedReader(
						new InputStreamReader(System.in));

				System.out.println("Enter number of operation you want:\n"
						+ "1: Add a new Domain-Password pair\n"
						+ "2: Delete a Domain-Password pair\n"
						+ "3: Update a Domain-Password pair\n"
						+ "4: List your Domain-Password pairs\n" + "5: Exit");
				String op = reader.readLine();

				if (op.equals("1")) {
					System.out
							.println("Enter your new Domain-Password pair seperated by a space\n"
									+ "e.g www.facebook.com mypassword");
					String pair = reader.readLine();
					String[] splits = pair.split(" ");
					if (splits.length == 2) {
						String paddedPass = passwordPadding(splits[1])
								+ splits[0];
						Table.domains.add(splits[0]);
						String passEncrypted = EncryptionDecryptionWrapper
								.encrypt(paddedPass, userHash);
						String domainMac =toHex(
								EncryptionDecryptionWrapper.encryptHmac(
										splits[0], userHash));
						table.addPasword(domainMac, passEncrypted);
					} else
						System.out.println("Operation failed");

				} else if (op.equals("2")) {
					System.out
							.println("Enter your old Domain-Password pair to remove seperated by a space\n"
									+ "e.g www.facebook.com mypassword");
					String pair = reader.readLine();
					String splits[] = pair.split(" ");
					if (splits.length == 2) {
						String paddedPass = passwordPadding(splits[1]);
						String passEncrypted = EncryptionDecryptionWrapper
								.encrypt(paddedPass, userHash);
						String domainMac = toHex(
								EncryptionDecryptionWrapper.encryptHmac(
										splits[0], userHash));
						table.removePasword(domainMac, passEncrypted);
					} else
						System.out.println("Operation failed");

				} else if (op.equals("3")) {
					System.out
							.println("Enter your Domain, old Password and new Password to update seperated by spaces\n"
									+ "e.g www.facebook.com myOldPassword myNewPassword");

					String pair = reader.readLine();
					String splits[] = pair.split(" ");
					if (splits.length == 3) {
						String oldPaddedPass = passwordPadding(splits[1]);
						String oldPassEncrypted = EncryptionDecryptionWrapper
								.encrypt(oldPaddedPass, userHash);
						String newPaddedPass = passwordPadding(splits[2]);
						String newPassEncrypted = EncryptionDecryptionWrapper
								.encrypt(newPaddedPass, userHash);

						String domainMac = toHex(
								EncryptionDecryptionWrapper.encryptHmac(
										splits[0], userHash));

						table.update(domainMac, oldPassEncrypted,
								newPassEncrypted);
					} else
						System.out.println("Operation failed");

				} else if (op.equals("4")) {

					table.printTable(userHash);

				} else if (op.equals("5")) {
					System.out.println("Return to main menu");
					return;
				} else {
					System.out
							.println("No operation matched, Enter operation number again");
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

		}
	}

	public void start() throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException {
		BufferedReader reader = new BufferedReader(new InputStreamReader(
				System.in));
		System.out.println("create new user (n)/ login (l)");
		String s = reader.readLine();
		System.out.println("Enter user password");
		String pass = reader.readLine();
		loadTables();
		if (s.equals("l")) {

			table = validatePassword(pass);
			byte[] hash = getHash(pass);
			if (table != null) {
				System.out.println("Found");
				userStart(hash);
			} else
				System.out.println("notFound");
		} else {

			byte hash[] = authUser(pass);
			System.out.println(toHex(hash));
			addUser(hash);
			// System.out.println(hash.length);
		}
		saveTables();
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

	public static byte[] fromHex(String hex) throws NoSuchAlgorithmException {
		byte[] bytes = new byte[hex.length() / 2];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2),
					16);
		}
		return bytes;
	}

	public static void main(String[] args) throws NoSuchAlgorithmException,
			InvalidKeySpecException, IOException {
		DataBase b = new DataBase();
		b.start();
	}

}
