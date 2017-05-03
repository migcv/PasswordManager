package pm;

import java.rmi.*;
import java.security.Key;
import java.util.ArrayList;

public interface ServerService extends Remote {

	public ArrayList<byte[]> init(Key publicKey, byte[] signature) throws RemoteException;

	public void register(Key publicKey, byte[] user_id, byte[] nonce, byte[] iv, byte[] signature) throws RemoteException;

	public ArrayList<byte[]> put(Key publicKey, byte[] user_id, byte[] read_id, byte[] domain, byte[] username, byte[] password,
			byte[] timestamp, byte[] write_rank, byte[] valueSignature, byte[] nonce, byte[] iv, byte[] signature)
			throws RemoteException;

	public ArrayList<byte[]> get(Key publicKey, byte[] user_id, byte[] read_id, byte[] domain, byte[] username,
			byte[] nonce, byte[] iv, byte[] signature) throws RemoteException;

}