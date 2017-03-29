package pm;

import java.rmi.*;
import java.security.Key;
import java.util.ArrayList;

public interface ServerService extends Remote {

	public ArrayList<byte[]> init(Key publicKey, byte[] signature) throws RemoteException;

	public void register(Key publicKey, byte[] id, byte[] n, byte[] iv, byte[] signature) throws RemoteException;

	public void put(Key publicKey, byte[] id, byte[] domain, byte[] username, byte[] password, byte[] iv, byte[] n,
			byte[] signature) throws RemoteException;

	public ArrayList<byte[]> get(Key publicKey, byte[] id, byte[] domain, byte[] username, byte[] iv, byte[] n,
			byte[] signature) throws RemoteException;

}