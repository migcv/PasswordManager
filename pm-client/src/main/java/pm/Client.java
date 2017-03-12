package pm;

import java.rmi.Naming;

import pm.ServerService;

public class Client {

	public static void main(String[] args) throws Exception {

		Library c = new Library();
		c.init("password".toCharArray(), "alias");
		System.out.println("Init");
		c.register_user();
		System.out.println("Register");
		c.save_password("www.google.com".getBytes(), "Miguel".getBytes(), "Macaco".getBytes());
		System.out.println("Save");
		System.out.println(new String(c.retrieve_password("www.google.com".getBytes(), "Miguel".getBytes()), "UTF-8"));
		System.out.println("Retrieve");
		c.close();

		// c.playGame(server);
		// c.congratulate();

	}

}
