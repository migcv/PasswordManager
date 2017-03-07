package pm;
import java.rmi.*;
import java.security.KeyStore;

public interface ServerService extends Remote{

	abstract public void init(KeyStore ks) throws RemoteException;
	abstract public void register_user() throws RemoteException;
	abstract public void save_password(byte[] domain, byte[] username, byte[] password) throws RemoteException;
	abstract public byte[] retrieve_password(byte[] domain, byte[] username) throws RemoteException;
	abstract public void close() throws RemoteException;
	
}