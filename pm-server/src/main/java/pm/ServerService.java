package pm;

import java.rmi.*;
import java.security.Key;
import java.util.ArrayList;

public interface ServerService extends Remote {

	public ArrayList<byte[]> init(Key publicKey, byte[] signature) throws RemoteException;

	public void register(Key publicKey, byte[] n, byte[] iv) throws RemoteException;

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password, byte[] iv, byte[] signature,
			byte[] n) throws RemoteException;

	public ArrayList<byte[]> get(Key publicKey, byte[] domain, byte[] username, byte[] iv, byte[] signature, byte[] n)
			throws RemoteException;

}