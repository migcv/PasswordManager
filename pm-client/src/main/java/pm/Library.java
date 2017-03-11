package pm;

import java.rmi.Naming;
import java.security.*;
import java.security.cert.X509Certificate;

public class Library {

	public void init(char[] password, String alias, KeyStore... ks) {
		KeyManagement ck = new KeyManagement();
		if (ks.length == 0) {
			try {
				ck.generateKeyPair(password, alias);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		//Nao sei se isto pode ser assim
		try {
			ck.getPublicKey(ks[0], alias, password);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void register_user(ServerService server) {
		KeyManagement ck = new KeyManagement();
		PublicKey pk = ck.getPk();
		
		//Nao entendo o que é que eles querem aqui
	}

	public void save_password(byte[] domain, byte[] username, byte[] password) {
		// Aqui tem que se fazer a cena da hash e enviar a password encriptada
	}

	public byte[] retrieve_password(byte[] domain, byte[] username) {
		return null;
	}

	public void close() {
	}
	
	public static void main(String[] args) throws Exception {
    	
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
    		c.register_user(server);
    		//c.playGame(server);
    		//c.congratulate();
    		
    	} catch (Exception e) {
    		System.out.println("Houve problemas: " + e.getMessage());
    	}
    	
    }

}
