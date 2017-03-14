package pm;

import java.rmi.Naming;
import java.security.Provider;
import java.security.Security;
import java.util.Enumeration;

import pm.ServerService;

public class Client {

	public static void main(String[] args) throws Exception {

		Library c = new Library();
		
		c.init("password".toCharArray(), "alias");
		System.out.println("Init");
		
		c.register_user();
		System.out.println("Register");
		
		c.save_password("www.google.com".getBytes(), "Miguel".getBytes(), "Macaco".getBytes());
		System.out.println("Save: www.google.com, Miguel, Macaco");
		
		System.out.println("Retrieve: " + new String(c.retrieve_password("www.google.com".getBytes(), "Miguel".getBytes()), "UTF-8"));
		
		c.save_password("www.google.com".getBytes(), "Miguel".getBytes(), "Chimpaze".getBytes());
		System.out.println("Save: www.google.com, Miguel, Chimpaze");
		
		System.out.println("Retrieve: " + new String(c.retrieve_password("www.google.com".getBytes(), "Miguel".getBytes()), "UTF-8"));
		
		c.close();

	}

}
