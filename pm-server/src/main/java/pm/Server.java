package pm;
import java.rmi.*;
import java.rmi.server.*;
import java.security.KeyStore;

public class Server extends UnicastRemoteObject implements ServerService{

	private static final long serialVersionUID = 1L;
	
	protected Server() throws RemoteException {
		super();
		// TODO Auto-generated constructor stub
	}


	public void init(KeyStore ks) throws RemoteException {
		// TODO Auto-generated method stub
		
	}

	public void register_user() throws RemoteException {
		// TODO Auto-generated method stub
		
	}

	public void save_password(byte[] domain, byte[] username, byte[] password) throws RemoteException {
		// TODO Auto-generated method stub
		
	}

	public byte[] retrieve_password(byte[] domain, byte[] username) throws RemoteException {
		// TODO Auto-generated method stub
		return null;
	}

	public void close() throws RemoteException {
		// TODO Auto-generated method stub
		
	}

}
