package pm;
import java.security.KeyStore;

public class Library {

	public void init(KeyStore ks){}
	
	public void register_user(){}
	
	public void save_password(byte[] domain, byte[] username, byte[] password){}
	
	public byte[] retrieve_password(byte[] domain, byte[] username){
		return null;
	}
	
	public void close(){}
}
