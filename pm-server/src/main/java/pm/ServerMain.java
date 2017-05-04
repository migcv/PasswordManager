package pm;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.rmi.registry.*;

public class ServerMain {

	public static void main(String[] args) {

		int registryPort = 0;

		System.setSecurityManager(new SecurityManager());
		ServerService server = null;

		// Load the state of the server
		server = loadState();
		try {
			// If the load returned null, create new Server instance
			if (args.length == 1) {
				registryPort = Integer.parseInt(args[0]);
				if (server == null) {
					server = new Server(registryPort);
				}
			}
			if (args.length == 2) {
				registryPort = Integer.parseInt(args[1]);
				server = new ByzantineServer(registryPort, args[0]);
			}
			
			// Registry Server
			Registry reg = LocateRegistry.createRegistry(registryPort);
			reg.rebind("ServerService", server);
			System.out.println("Password Manager Server ready, port: " + registryPort);
		} catch (Exception e) {
			System.out.println("Ups...something is wrong: " + e.getMessage());
			e.printStackTrace();
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
		} catch (IOException e) {
			System.out.println("File not found, generating new Server instance!");
		} catch (ClassNotFoundException c) {
			System.out.println("ServerService class not found");
			c.printStackTrace();
		}
		return null;
	}

}
