package pm.test;

import java.io.UnsupportedEncodingException;
import java.rmi.Naming;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import junit.framework.Assert;
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
		System.out.println("Init");
		c.register_user();
		System.out.println("Register");
		c.save_password("www.google.com".getBytes(), "Miguel".getBytes(), "Macaco".getBytes());
		System.out.println("Save");
		String password = new String(c.retrieve_password("www.google.com".getBytes(), "Miguel".getBytes()), "UTF-8");
		System.out.println(password);
		System.out.println("Retrieve");
		c.close();
		Assert.assertEquals(password, "Macaco");
	}

}
