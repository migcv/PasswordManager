package pm;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.rmi.registry.*;

public class ServerMain {

	protected static int N = 10;

	public static void main(String[] args) {

		int registryPort = 10000;
		System.setSecurityManager(new SecurityManager());
		ServerService server = null;

		// Load the state of the server
		server = loadState();
		for (int i = 0; i < N; i++) {
			try {
				// If the load returned null, create new Server instance
				if (server == null) {
					server = new Server();
				}
				// Registry Server
				Registry reg = LocateRegistry.createRegistry(registryPort + i);
				reg.rebind("ServerService", server);
				System.out.println("Password Manager Server ready!" + registryPort + i);
			} catch (Exception e) {
				System.out.println("Ups...something is wrong: " + e.getMessage());
				e.printStackTrace();
			}
		}
	}

	// Load the state of the server from file pmserver.ser
	private static ServerService loadState() {
		try {
			FileInputStream fileIn = new FileInputStream("pmserver.ser");
			ObjectInputStream in = new ObjectInputStream(fileIn);
			ServerService server = (ServerService) in.readObject();
			System.out.println("Server loaded!");
			in.close();
			fileIn.close();
			return server;
		} catch (IOException i) {
			System.out.println("File not found, generating new Server instance!");
		} catch (ClassNotFoundException c) {
			System.out.println("ServerService class not found");
			c.printStackTrace();
		}
		return null;
	}

}
