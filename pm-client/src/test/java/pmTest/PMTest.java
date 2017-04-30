package pmTest;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;
import java.rmi.Naming;
import java.security.KeyStore;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import pm.Library;
import pm.ServerService;

public class PMTest {

	private static ServerService server = null;

	@BeforeClass
	public static void oneTimeSetUp() {
		if (System.getSecurityManager() == null) {
			System.setSecurityManager(new SecurityManager());
		} else
			System.out.println("Já tem um cenas");

		try {

			server = (ServerService) Naming.lookup("//localhost:10000/ServerService");
			System.out.println("Encontrou o servidor");

		} catch (Exception e) {
			System.out.println("Houve problemas: " + e.getMessage());
		}

	}

	@Test
	public void sucess() throws UnsupportedEncodingException {

		Library c = new Library();
		c.init("password".toCharArray(), "alias", null);
		c.register_user();
		c.save_password("www.google.com".getBytes(), "Miguel".getBytes(), "Viegas".getBytes());
		String password = new String(c.retrieve_password("www.google.com".getBytes(), "Miguel".getBytes()), "UTF-8");
		c.close();
		assertEquals(password, "Viegas");
	}

	@Test
	public void sucessWithKeyStore() throws UnsupportedEncodingException {

		Library c = new Library();
		KeyStore ks = c.getInstanceOfKeyStore("password".toCharArray(), "monkey");
		c.init("password".toCharArray(), "monkey", ks);
		c.register_user();
		c.save_password("www.google.com".getBytes(), "Miguel".getBytes(), "Viegas".getBytes());
		String password = new String(c.retrieve_password("www.google.com".getBytes(), "Miguel".getBytes()), "UTF-8");
		c.close();
		assertEquals(password, "Viegas");
	}

	@Test
	public void sucessChangingPassword() throws UnsupportedEncodingException {

		Library c = new Library();
		c.init("password".toCharArray(), "alias", null);
		c.register_user();
		c.save_password("www.google.com".getBytes(), "Alice".getBytes(), "SEC_16_17".getBytes());
		String pass1 = new String(c.retrieve_password("www.google.com".getBytes(), "Alice".getBytes()), "UTF-8");
		c.save_password("www.google.com".getBytes(), "Alice".getBytes(), "IST".getBytes());
		String pass2 = new String(c.retrieve_password("www.google.com".getBytes(), "Alice".getBytes()), "UTF-8");
		c.close();
		assertFalse(pass1.equals(pass2));
	}

	@Test
	public void sucessTwoLibrarys() {

		Library c = new Library();
		c.init("password".toCharArray(), "alias", null);
		c.register_user();
		c.save_password("www.google.com".getBytes(), "Alice".getBytes(), "SEC_16_17".getBytes());
		c.retrieve_password("www.google.com".getBytes(), "Alice".getBytes());
		c.close();

		Library c1 = new Library();
		c1.init("password1".toCharArray(), "alias1", null);
		c1.register_user();
		c1.save_password("www.google.com".getBytes(), "Bob".getBytes(), "SEC".getBytes());
		c1.retrieve_password("www.google.com".getBytes(), "Bob".getBytes());
		c1.close();

		assertFalse(c == c1);
	}
	
	@Test
	public void sucessTwoLibrarysAgain() throws UnsupportedEncodingException {

		Library c = new Library();
		Library c1 = new Library();
		
		c.init("password".toCharArray(), "alias", null);
		c1.init("password1".toCharArray(), "alias1", null);
		
		c.register_user();
		c.save_password("www.google.com".getBytes(), "Alice".getBytes(), "SEC_16_17".getBytes());
		
		c1.register_user();
		c1.save_password("www.google.com".getBytes(), "Bob".getBytes(), "SEC".getBytes());
		String pass1 = new String(c1.retrieve_password("www.google.com".getBytes(), "Bob".getBytes()), "UTF-8");
		
		String pass2 = new String(c.retrieve_password("www.google.com".getBytes(), "Alice".getBytes()), "UTF-8");		
		c.close();

		c1.save_password("www.pornhub.com".getBytes(), "Maria".getBytes(), "PALHOLHO".getBytes());
		String pass3 = new String(c1.retrieve_password("www.pornhub.com".getBytes(), "Maria".getBytes()), "UTF-8");
		c1.close();

		assertFalse(pass1 == pass2);
		assertFalse(pass2 == pass3);
		assertFalse(pass1 == pass3);
	}
	
}
