package test;

import java.rmi.Naming;

import org.junit.*;

import org.junit.Test;

import pm.ServerService;

public class PMTest {

	/*private static ServerService server = null;
	
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
	public void sucess() {
		
		Library c = new Library();
		c.init("password".toCharArray(), "alias");
		System.out.println("Init");
		c.register_user();
		System.out.println("Register");
		c.save_password("www.google.com".getBytes(), "Miguel".getBytes(), "Macaco".getBytes());
		System.out.println("Save");
		System.out.println(new String(c.retrieve_password("www.google.com".getBytes(), "Miguel".getBytes()), "UTF-8"));
		System.out.println("Retrieve");
		c.close();
	}*/
}