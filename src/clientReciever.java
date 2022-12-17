import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;

public class clientReciever {
	private static Map<String, String> availableClients;
	private static Socket socket;

	public static void main(String[] args) throws Exception, IOException {
		int userId = Integer.parseInt(args[0]);
		String password = args[1];

		String[] clientAddress = args[2].split(":");
		String address = clientAddress[0];
		int port = Integer.parseInt(clientAddress[1]);

		System.setProperty("javax.net.ssl.trustStore", "keystore.server");
		System.setProperty("javax.net.ssl.trustStorePassword", "ninis1234");

		SocketFactory sf = SSLSocketFactory.getDefault( );
		Socket socket = sf.createSocket(address, 23456);

		ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
		ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
		
		System.out.println(port);
		
		ServerSocket sSoc = null;
		try {
			ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();
			sSoc = ssf.createServerSocket(port);
		} catch (Exception e) {
			e.printStackTrace();
		}

		socket.close();
		
		//add(userId, password, inStream, outStream);

		while(true) {
			
			socket = sSoc.accept();
			
			try {
				ObjectInputStream inStream2 = new ObjectInputStream(socket.getInputStream());
				ObjectOutputStream outStream2 = new ObjectOutputStream(socket.getOutputStream());
				receivesFile(String.valueOf(userId), password, inStream2, outStream2);
				System.out.println("aaaaa");
			} catch (Exception e) {
				//e.printStackTrace();
			}

			outStream.close();
			inStream.close();
			socket.close();
		}
	}

	private static void add(int userId, String password, ObjectInputStream inStream, ObjectOutputStream outStream) throws Exception {
		File kfile = new File("keystore." + userId);  //keystore
		if(!kfile.isFile()) { 
			System.out.println("aaaaaa");
			Cifra.main(String.valueOf(userId), password);					
		} 

		outStream.writeObject(String.valueOf(userId)); //nome
		availableClients = (HashMap<String, String>) inStream.readObject();
	}

	private static void receivesFile(String userId, String password, ObjectInputStream inStream2, ObjectOutputStream outStream2) throws IOException, Exception {

		File kfile = new File("keystore." + userId);  //keystore
		if(!kfile.isFile()) { 
			Cifra.main(String.valueOf(userId), password);					
		} 

		FileInputStream kfilein = new FileInputStream("keystore." + userId);  //keystore
		KeyStore kstore = KeyStore.getInstance("JKS");
		kstore.load(kfilein, password.toCharArray());

		Certificate c = (Certificate) kstore.getCertificate(String.valueOf(userId)); 
		PublicKey pubk = c.getPublicKey();
		outStream2.writeObject(pubk); //sends public key to sender

		PublicKey pubk_sender = (PublicKey) inStream2.readObject();

		// old mac
		byte[] array3 = (byte[]) inStream2.readObject();

		//Recieves the file

		BufferedOutputStream fileBOS = new BufferedOutputStream(new FileOutputStream("./client/" + userId + ".cif"));
		byte[] array = new byte[1024];
		int i = inStream2.read(array);
		while(i != -1) {
			fileBOS.write(array, 0, i);
			i = inStream2.read(array);
		}
		fileBOS.close();

		// Decrypt the file

		//READ WRAPPED KEY
		byte[] keyEncoded = (byte[]) inStream2.readObject();

		//GET PRIVATE KEY
		Key myPrivateKey = kstore.getKey(String.valueOf(userId), password.toCharArray()); 

		//GET RANDOM AES KEY CREATED IN CIPHER
		Cipher cRSA = Cipher.getInstance("RSA");
		cRSA.init(Cipher.UNWRAP_MODE, myPrivateKey); 
		Key keyAES = cRSA.unwrap(keyEncoded, "AES", Cipher.SECRET_KEY);

		//DECRYPT CIPHER
		Cipher cAES = Cipher.getInstance("AES");
		cAES.init(Cipher.DECRYPT_MODE, keyAES);

		//DECRYPT FILE WITH AES KEY
		FileInputStream fileFIS = new FileInputStream("./user_directories/data/" + userId + ".cif");
		CipherOutputStream fileCOS = new CipherOutputStream(outStream2, cAES);
		byte[] array2 = new byte[1024];
		//outStream2.writeObject(temp); //sends file size
		int x1 = 0;
		while((x1 = fileFIS.read(array2, 0, 1024)) > 0) {
			fileCOS.write(array2, 0, x1);
			fileCOS.flush();
		}
		System.out.println("Message sent to client of id: " + userId);
		fileFIS.close();
		fileCOS.close();

		// Hash para testar a integridade

		PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
		SecretKey key = kf.generateSecret(keySpec);

		// new mac
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(key);
		mac.update(array2);
		byte[] arrayFinal = mac.doFinal();

		String new_mac = new String(array2);
		String old_mac = new String(array3);
		if(old_mac.equals(new_mac)) {
			System.out.println("MAC of message is correct");
		} else{
			throw new Exception("MAC of the message is invalid");
		}

	}
}
