/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author asus
 */
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
public class chat extends Thread{
   private Socket socket;
   private String name;
   private PrivateKey privateKey;
   private KeyPair keyPair;
   chat(String name,KeyPair keyPair) throws Exception
   {
       this.keyPair=keyPair;
       this.privateKey=keyPair.getPrivate();
       this.name=name;
       socket=null;
       System.out.println("In Constructor");
   }
   private static PublicKey getPublicKey(String base64PublicKey){
        PublicKey publicKey = null;
        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }
   private static byte[] encrypt(String key, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");  
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(key));  

        return cipher.doFinal(message.getBytes());  
    }
   public static byte[] decrypt(PrivateKey key, byte [] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encrypted);
    }
   @Override
   public void run()
   {
       System.out.println("Accept Thread Running");
       try{
            ServerSocket ss=new ServerSocket(3025);
            while(true)
            {
                 socket=ss.accept();
                 System.out.println("Socket Connected");
                 DataInputStream dis=new DataInputStream(socket.getInputStream());
                 String enckey=dis.readUTF();
                 String tech=enckey.substring(0,3);
                 enckey=enckey.substring(5);
                 System.out.println(enckey+"\n"+tech);
                 String secretKey=new String(decrypt(privateKey,Base64.getDecoder().decode(enckey)));
                 System.out.println("SecretKey: "+secretKey);
                 ClientHandler ob=new ClientHandler(socket,name,tech,secretKey,keyPair);
                 ob.setVisible(true);
                 ob.t.start();
            }
       }
       catch(IOException E)
       {
           System.out.println("Nth Level Lol "+E.toString());
       }
       catch(Exception E)
       {
           System.out.println("nth Level Lol "+E.toString());
       }
   }
   public void connect(String ip,String tech,String pubKeyRSA)throws Exception
   {
       Socket socket=new Socket(ip,3025);
       System.out.println("Connected");
       String encKey,secretKey;
       SecretKey key;
       if(tech.equals("AES"))
       {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            key = keyGen.generateKey();
            secretKey=Base64.getEncoder().encodeToString(key.getEncoded());
            encKey=Base64.getEncoder().encodeToString(encrypt(pubKeyRSA,secretKey));
            encKey="AES**"+encKey;
       }
       else
       {
            key = KeyGenerator.getInstance("DES").generateKey();
            secretKey=Base64.getEncoder().encodeToString(key.getEncoded());
            encKey=Base64.getEncoder().encodeToString(encrypt(pubKeyRSA,secretKey));
            encKey="DES**"+encKey;
       }
       DataOutputStream dos=new DataOutputStream(socket.getOutputStream());
       dos.writeUTF(encKey);
       System.out.println("Key Sent "+encKey+"\n"+secretKey);
       ClientHandler ob=new ClientHandler(socket,name,tech,secretKey,keyPair);
       ob.setVisible(true);
       ob.t.start();
   }
}
