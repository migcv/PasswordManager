package pmTest;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;
import java.rmi.Naming;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import pm.Library;
import pm.ServerService;
import pm.exception.DomainOrUsernameDoesntExistException;

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

	@AfterClass
	public static void oneTimeTearDown() {

	}

	@Before
	public void setUp() {
	}

	@After
	public void tearDown() {
	}

	@Test
	public void sucess() throws UnsupportedEncodingException {

		Library c = new Library();
		c.init("password".toCharArray(), "alias");
		c.register_user();
		c.save_password("www.google.com".getBytes(), "Miguel".getBytes(), "Viegas".getBytes());
		String password = new String(c.retrieve_password("www.google.com".getBytes(), "Miguel".getBytes()), "UTF-8");
		c.close();
		assertEquals(password, "Viegas");
	}

	@Test
	public void sucessChangingPassword() throws UnsupportedEncodingException {

		Library c = new Library();
		c.init("password".toCharArray(), "alias");
		c.register_user();
		c.save_password("www.google.com".getBytes(), "Alice".getBytes(), "SEC_16_17".getBytes());
		String pass1 = new String(c.retrieve_password("www.google.com".getBytes(), "Alice".getBytes()), "UTF-8");
		c.save_password("www.google.com".getBytes(), "Alice".getBytes(), "IST".getBytes());
		String pass2 = new String(c.retrieve_password("www.google.com".getBytes(), "Alice".getBytes()), "UTF-8");
		c.close();
		assertFalse(pass1.equals(pass2));
	}

	@Test(expected = DomainOrUsernameDoesntExistException.class)
	public void UsernameDoesNotExists() {
		
		Library c = new Library();
		c.init("password".toCharArray(), "alias");
		c.register_user();
		c.save_password("www.google.com".getBytes(), "Alice".getBytes(), "SEC_16_17".getBytes());
		c.retrieve_password("www.google.com".getBytes(), "Alice".getBytes());
		c.retrieve_password("www.google.com".getBytes(), "Macaco".getBytes());

	}
	
	@Test(expected = DomainOrUsernameDoesntExistException.class)
	public void DomainDoesNotExists() {
		
		Library c = new Library();
		c.init("password".toCharArray(), "alias");
		c.register_user();
		c.save_password("www.google.com".getBytes(), "Alice".getBytes(), "SEC_16_17".getBytes());
		c.retrieve_password("www.google.com".getBytes(), "Alice".getBytes());
		c.retrieve_password("www.ist.com".getBytes(), "Alice".getBytes());

	}

}
