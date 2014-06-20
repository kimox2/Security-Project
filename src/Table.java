import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class Table implements Serializable {

	private static final long serialVersionUID = 1L;
	public HashMap<String, HashSet<String>> table = new HashMap<String, HashSet<String>>();
	public static HashSet<String> domains = new HashSet<String>();

	public void addPasword(String domain, String password) {
		
		if (table.containsKey(domain))
			table.get(domain).add(password);
		else {
			HashSet<String> passwords = new HashSet<String>();
			passwords.add(password);
			table.put(domain, passwords);
		}
	}

	public void removePasword(String domain, String password) {
		if (table.containsKey(domain))
			table.get(domain).remove(password);
	}

	public void update(String domain, String oldPass, String newPass) {
		removePasword(domain, oldPass);
		addPasword(domain, newPass);
	}

	public String getDomainName(String hashDomain, byte[] userHash)
			throws InvalidKeyException, NoSuchAlgorithmException {
		for (String s : domains) {
			if (EncryptionDecryptionWrapper.validate(s, hashDomain, userHash))
				return s;
		}
		return null;

	}

	public void printTable(byte[] userHash) throws NoSuchAlgorithmException, InvalidKeyException {
		for (Map.Entry<String, HashSet<String>> e : table.entrySet()) {
			System.out.println("print domain name "+e.getKey());
			String domainName=getDomainName(e.getKey(), userHash);
			System.out.println("Domain: " + domainName);
			HashSet<String> passwords = e.getValue();
			System.out.println("Passwords: ");
			for (String s : passwords) {
				String decryptedPass = EncryptionDecryptionWrapper.decrypt(
						DataBase.fromHex(s), userHash);
				decryptedPass = decryptedPass.replace("$", "");
				System.out.println(decryptedPass.substring(0, decryptedPass.length()-domainName.length()));
			}
		}
	}

	public static void main(String[] args) {
		HashMap<String, ArrayList<String>> hm = new HashMap();
		ArrayList<String> li = new ArrayList();
		hm.put("kalo", li);
		hm.get("kalo").add("yaret");
		System.out.println("=" + hm.get("kalo"));
	}
}
