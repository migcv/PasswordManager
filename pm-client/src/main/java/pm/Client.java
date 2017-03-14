package pm;

import java.rmi.Naming;
import java.security.Provider;
import java.security.Security;
import java.util.Enumeration;

import pm.ServerService;

public class Client {

	public static void main(String[] args) throws Exception {
		Provider p[] = Security.getProviders();
	      for (int i = 0; i < p.length; i++) {
	        System.out.println(p[i]);
	        for (Enumeration e = p[i].keys(); e.hasMoreElements();)
	          System.out.println("\t" + e.nextElement());
	      }
		Library c = new Library();
		c.init("password".toCharArray(), "alias");
		System.out.println("Init");
		c.register_user();
		System.out.println("Register");
		c.save_password("www.google.com".getBytes(), "Miguel".getBytes(), "Macaco".getBytes());
		System.out.println("Save");
		System.out.println(new String(c.retrieve_password("www.google.com".getBytes(), "Miguel".getBytes()), "UTF-8"));
		System.out.println("Retrieve");
		c.save_password("www.google.com".getBytes(), "Miguel".getBytes(), "Mamas".getBytes());
		System.out.println("Save");
		System.out.println(new String(c.retrieve_password("www.google.com".getBytes(), "Miguel".getBytes()), "UTF-8"));
		System.out.println("Retrieve");
		c.close();

	}

}
