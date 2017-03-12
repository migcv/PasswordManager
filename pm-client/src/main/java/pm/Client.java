package pm;

import java.rmi.Naming;

import pm.ServerService;

public class Client {

	public static void main(String[] args) throws Exception {

		Library c = new Library();
		c.init("password".toCharArray(), "alias");
		c.register_user();
		c.save_password("www.google.com".getBytes(), "Miguel".getBytes(), "Macaco".getBytes());
		c.retrieve_password("www.google.com".getBytes(), "Miguel".getBytes());
		c.close();

		// c.playGame(server);
		// c.congratulate();

	}

}
