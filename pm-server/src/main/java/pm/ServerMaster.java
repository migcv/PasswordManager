package pm;

import java.io.IOException;

public class ServerMaster {
	
	private static final int F = 5;
	
	private static final int N_SERVERS = F * 3 + 1;
	
	private static final int PORT = 10000;

	public static void main(String[] args) {
		Process p;
		System.out.println("Launching " + N_SERVERS + " servers!");
		try {
			for (int i = 0; i < N_SERVERS; i++) {
				if(!System.getProperty("os.name").contains("Mac")) { // Run in Windows
					p = Runtime.getRuntime().exec("cmd /c start cmd.exe /k java -cp target/classes pm.ServerMain " + (PORT + i));
					p.waitFor();
				} else { // Run in Mac
					p = Runtime.getRuntime().exec("");
					p.waitFor();
				}
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

}
