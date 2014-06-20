import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;

public class Table implements Serializable {

	private static final long serialVersionUID = 1L;
	public HashMap<String, ArrayList<String>> table = new HashMap<String, ArrayList<String>>();

	public void addPasword(String domain, String password) {
		if (table.containsKey(domain))
			table.get(domain).add(password);
		else {
			ArrayList<String> passwords = new ArrayList<>();
			passwords.add(password);
			table.put(domain, passwords);
		}
	}

	public static void main(String[] args) {
		HashMap<String, ArrayList<String>> hm = new HashMap<>();
		ArrayList<String> li = new ArrayList<>();
		hm.put("kalo", li);
		hm.get("kalo").add("yaret");
		System.out.println("=" + hm.get("kalo"));
	}
}
