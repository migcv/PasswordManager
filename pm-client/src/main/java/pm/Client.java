package pm;

import java.rmi.Naming;

import pm.ServerService;

public class Client {

	/*public static void main(String[] args) throws Exception {
    	
    	if (System.getSecurityManager() == null) {
    		System.setSecurityManager(new SecurityManager());
    	}
    	else System.out.println("Já tem um cenas");
    	
    	ServerService server = null;
    	
    	try {
    		
    		server = (ServerService) Naming.lookup("//localhost:10000/ServerService");
    		System.out.println("Encontrou o servidor");
    		
    		Library c = new Library();
    		c.init("password".toCharArray(), "alias");
    		//c.playGame(server);
    		//c.congratulate();
    		
    	} catch (Exception e) {
    		System.out.println("Houve problemas: " + e.getMessage());
    	}
    	  /* TO DO 
    }*/

}
