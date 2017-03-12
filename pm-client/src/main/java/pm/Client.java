package pm;

import java.rmi.Naming;

import pm.ServerService;

public class Client {

	public static void main(String[] args) throws Exception {

		Library c = new Library();
		c.init("password".toCharArray(), "alias");
		c.register_user();

		// c.playGame(server);
		// c.congratulate();

	}

}
