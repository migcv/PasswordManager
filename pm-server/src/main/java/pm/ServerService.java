package pm;

import java.rmi.*;
import java.security.Key;
import java.util.ArrayList;

public interface ServerService extends Remote {

	public ArrayList<byte[]> init(Key publicKey, byte[] signature) throws RemoteException;

	public void register(Key publicKey, byte[] user_id, byte[] n, byte[] iv, byte[] signature) throws RemoteException;

	public void put(Key publicKey, byte[] user_id, byte[] domain, byte[] username, byte[] password, byte[] timestamp, byte[] write_rank,
			byte[] valueSignature, byte[] iv, byte[] n, byte[] signature) throws RemoteException;

	public ArrayList<byte[]> get(Key publicKey, byte[] user_id, byte[] read_id, byte[] domain, byte[] username, byte[] iv, byte[] n,
			byte[] signature) throws RemoteException;

}