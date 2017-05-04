package pm;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.Key;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

public class ByzantineServer extends UnicastRemoteObject implements ServerService {

	private static final long serialVersionUID = 1L;

	private int port;
	private String flag = "";
	private Server s;

	protected ByzantineServer(int port, String flag) throws RemoteException {
		s = new Server(port);
		this.flag = flag;
	}

	public ArrayList<byte[]> init(Key publicKey, byte[] sig) throws RemoteException {

		System.out.println("!---------------------------BYZANTINE---------------------------!");
		
		System.out.println(this.port + " > Received Request <Init>");
		return s.init(publicKey, sig);
	}

	public void register(Key publicKey, byte[] id, byte[] nonce, byte[] iv, byte[] signature) throws RemoteException {

		System.out.println(port + " > Received Request <Register>");

		s.register(publicKey, id, nonce, iv, signature);
	}

	public ArrayList<byte[]> put(Key publicKey, byte[] id, byte[] read_id, byte[] domain, byte[] username,
			byte[] password, byte[] timestamp, byte[] write_rank, byte[] valueSignature, byte[] nonce, byte[] iv,
			byte[] signature) throws RemoteException {

		System.out.println(port + " > Received Resquest <Put>");
		
		if (flag.equals("-pp")) {
			
			byte[] b = password;
			
			b[0] &= (byte) ~(1 << 5);
			
			if(!Arrays.equals(b, password)){
				System.out.println("DIFFERENT!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
			}
			
			return s.put(publicKey, id, read_id, domain, username, password, timestamp, write_rank, valueSignature,
					nonce, iv, signature);
		}

		return s.put(publicKey, id, read_id, domain, username, password, timestamp, write_rank, valueSignature, nonce,
				iv, signature);
	}

	public ArrayList<byte[]> get(Key publicKey, byte[] user_id, byte[] read_id, byte[] domain, byte[] username,
			byte[] nonce, byte[] iv, byte[] signature) throws RemoteException {

		System.out.println(port + " > Request Received <Get>");

		return s.get(publicKey, user_id, read_id, domain, username, nonce, iv, signature);
	}

}
