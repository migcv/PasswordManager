package pm;
import java.rmi.*;
import java.rmi.server.*;
import java.security.Key;

public class Server extends UnicastRemoteObject implements ServerService{

	private static final long serialVersionUID = 1L;
	
	
	protected Server() throws RemoteException {
		super();
		// TODO Auto-generated constructor stub
	}


	public void register(Key publicKey) throws RemoteException {
		// TODO Auto-generated method stub
		
	}


	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
		// TODO Auto-generated method stub
		
	}


	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
		// TODO Auto-generated method stub
		return null;
	}


}
