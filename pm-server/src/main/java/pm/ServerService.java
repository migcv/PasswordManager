package pm;

import java.rmi.*;
import java.security.Key;

public interface ServerService extends Remote {
	
	public Key init(Key publicKey) throws RemoteException;

	public void register(Key publicKey) throws RemoteException;
	
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password, byte[] signature) throws RemoteException;
	
	public byte[] get(Key publicKey, byte[] domain, byte[] username, byte[] signature) throws RemoteException;
	
}