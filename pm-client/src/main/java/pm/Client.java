package pm;

import java.security.KeyStore;

public class Client {

	public static void main(String[] args) throws Exception {

		Library c = new Library();
		
		KeyStore ks = c.getInstanceOfKeyStore("password".toCharArray(), "alias");
		
		c.init("password".toCharArray(), "alias", ks);
		
		c.register_user();
		
		c.save_password("www.google.com".getBytes(), "Alice".getBytes(), "SEC_16_17".getBytes());
		System.out.println("save: [ www.google.com, Alice, SEC_16_17 ]");
		
		System.out.println("retrieve: [ www.google.com, Alice ] ==> " + new String(c.retrieve_password("www.google.com".getBytes(), "Alice".getBytes()), "UTF-8"));
		
		c.save_password("www.youtube.com".getBytes(), "Bob".getBytes(), "A_CES".getBytes());
		System.out.println("save: [ www.youtube.com, Bob, A_CES ]");
		
		c.save_password("www.google.com".getBytes(), "Alice".getBytes(), "IST".getBytes());
		System.out.println("save: [ www.google.com, Alice, IST ]");
		
		System.out.println("retrieve: [ www.youtube.com, Bob ] ==> " + new String(c.retrieve_password("www.youtube.com".getBytes(), "Bob".getBytes()), "UTF-8"));
		
		System.out.println("retrieve: [ www.google.com, Alice ] ==> " + new String(c.retrieve_password("www.google.com".getBytes(), "Alice".getBytes()), "UTF-8"));
		
		c.close();

	}

}
