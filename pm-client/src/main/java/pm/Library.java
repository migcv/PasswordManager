package pm;
import java.rmi.*;
import java.rmi.server.*;
import java.security.Key;
import java.util.Scanner;

public class Library {

	public void register(Key publicKey){}
	
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password){}
	
	public byte[] get(Key publicKey, byte[] domain, byte[] username){
		
		return null;
		
	}

}
