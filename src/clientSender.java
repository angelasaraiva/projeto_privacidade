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

public class clientSender {
	private static Map<String, List> availableClients;
	private static Socket socket;

	public static void main(String[] args) throws Exception, IOException {
		int userId = Integer.parseInt(args[0]);
		String password = args[1];
		String nameReceiver;

		String[] clientAddress = args[2].split(":");
		String address = clientAddress[0];
		int port = Integer.parseInt(clientAddress[1]);
		
		Socket socket = new Socket(address, 23456);

		ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
		ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());

		System.out.println(port);

		add(userId, password, inStream, outStream, port);

		Scanner myObj = new Scanner(System.in);
		System.out.println("Say what you wanna do (send <receiverName>): ");
		String message = myObj.nextLine();

		if (message.substring(0, 4).equals("send")) {
			nameReceiver = message.substring(5);
			System.out.println(nameReceiver);
			System.out.println("bbbbbb");

			sendFileMessage(userId, password, nameReceiver);
		}

		outStream.close();
		inStream.close();
		socket.close();
	}

	private static void add(int userId, String password, ObjectInputStream inStream, ObjectOutputStream outStream, int port)
			throws Exception {
		
		File kfile = new File("keystore." + userId);  //keystore
		if(!kfile.isFile()) { 
			System.out.println("aaaaaa");
			Cifra.main(String.valueOf(userId), password);					
		} 

		outStream.writeObject(String.valueOf(userId)); //nome
		outStream.writeObject(port);
		availableClients = (HashMap<String, List>) inStream.readObject();
		System.out.println(availableClients);
	}

	private static void sendFileMessage(int userId, String password, String nameReceiver) throws Exception { // SEND FILES

		// connection between client and server
		System.out.println("aaaaaa");
		File kfile = new File("keystore." + userId); // keystore
		if (!kfile.isFile()) {
			System.out.println("aaaaaa");
			Cifra.main(String.valueOf(userId), password);
		}

		// outStream.writeObject("listen");
		// outStream.writeObject(String.valueOf(userId)); //nome

		FileInputStream kfilein = new FileInputStream("keystore." + userId); // keystore
		KeyStore kstore = KeyStore.getInstance("JKS");
		kstore.load(kfilein, password.toCharArray());

		// List names = (ArrayList) inStream.readObject(); // names of clients
		// List addresses = (ArrayList) inStream.readObject();// addresses of clients
		// String availableClients = (String) inStream.readObject();
		// Map<String, String> availableClients = (HashMap<String, String>)
		// inStream.readObject();

		String clientAddress = null;
		String clientPort = null;
		// choose a client to chat
		if (availableClients.get(nameReceiver) != null) {
			clientAddress = (String) availableClients.get(nameReceiver).get(0);
			clientPort = (String) availableClients.get(nameReceiver).get(1);
		} else {
			System.out.println("This user doesn't exist.");
		}
		System.out.println(availableClients);
		System.out.println(clientAddress);
		System.out.println(clientPort);
		
		Socket newSocket = new Socket(clientAddress, Integer.valueOf(clientPort));

		// Socket newSocket = sf.createSocket(clientSocket.getInetAddress(),
		// clientSocket.getPort());

		ObjectInputStream inStream2 = new ObjectInputStream(newSocket.getInputStream());
		System.out.println("ccccccc");
		ObjectOutputStream outStream2 = new ObjectOutputStream(newSocket.getOutputStream());

		// NÃO PASSA DAQUI ----------------------------------------------
		// the clients send their public keys
		PublicKey pubk_receiver = (PublicKey) inStream2.readObject();
		Certificate c = (Certificate) kstore.getCertificate(String.valueOf(userId));
		PublicKey pubk = c.getPublicKey();
		outStream2.writeObject(pubk); // sends public key to receiver

		Scanner myObj1 = new Scanner(System.in);
		System.out.println("Enter message: ");
		String message = myObj1.nextLine();

		// Create Hash of the message

		PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
		SecretKey key_Mac = kf.generateSecret(keySpec);

		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(key_Mac);

		// BufferedOutputStream oos = new BufferedOutputStream(new
		// FileOutputStream("message_hash.txt"));
		byte buf[] = message.getBytes();
		mac.update(buf);
		outStream2.writeObject(mac.doFinal());
		// oos.close();

		// Gerar chave de sessão p/ comunicação com determinado(s) cliente(s)

		// GET RANDOM AES KEY
		KeyGenerator kg = KeyGenerator.getInstance("AES"); // generate random key for AES
		kg.init(128);
		SecretKey key = kg.generateKey();

		// CIPHER FILE WITH AES KEY
		Cipher cAES = Cipher.getInstance("AES");
		cAES.init(Cipher.ENCRYPT_MODE, key);
		byte buf2[] = message.getBytes();
		byte[] encryp_message = cAES.doFinal(buf2);
		kfilein.close();
		outStream2.writeObject(encryp_message);

		// Encrypt the AES key with the public key of the receiver

		// PERGUNTAR AO
		// PROFESSORR!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

		Cipher cRSA = Cipher.getInstance("RSA");
		cRSA.init(Cipher.WRAP_MODE, pubk_receiver);
		byte[] wrappedKey = cRSA.wrap(key);
		outStream2.writeObject(wrappedKey);

		// order of stuff received: list of available clients, public key of receiver
		// order of stuff sent: public key, hashed file, cipher file, wrapped AES key
		// (shared key)

	}
}
