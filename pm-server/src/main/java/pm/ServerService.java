package pm;

import java.rmi.*;
import java.security.Key;
import java.util.ArrayList;

public interface ServerService extends Remote {
	
	public ArrayList<byte[]> init(Key publicKey) throws RemoteException;

	public void register(Key publicKey) throws RemoteException;
	
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password, byte[] iv, byte[] signature) throws RemoteException;
	
	public ArrayList<byte[]> get(Key publicKey, byte[] domain, byte[] username, byte[] iv, byte[] signature) throws RemoteException;
	
}