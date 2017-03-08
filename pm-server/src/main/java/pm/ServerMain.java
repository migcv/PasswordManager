package pm;

import java.rmi.registry.*;

public class ServerMain {

	public static void main(String[] args){
		
		int registryPort = 10000;
		System.setSecurityManager(new SecurityManager());
		
		try {
			ServerService server = new Server();
			Registry reg = LocateRegistry.createRegistry(registryPort);
			reg.rebind("ServerService", server);
			System.out.println("Server ready");
		} catch (Exception e) {
			System.out.println("Server... broke? " + e.getMessage());
		}
		
	}

}
