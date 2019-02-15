
import com.mysql.jdbc.Connection;
import java.awt.RenderingHints.Key;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import java.lang.Exception;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author asus
 */

public class Manager {
    private String ip,name;
    private Connection con;
    Manager(String name,String ip) throws Exception
    {
        this.ip=ip;
        this.name=name;
        System.out.println("Name: "+name+" IP: "+ip);
        Class.forName("com.mysql.jdbc.Driver");
        String dbName = "cryptchat";
        String userName = "root";
        String password = "pass";
        String hostname = serverIP.IP;
        String port = "3306";
        String jdbcUrl = "jdbc:mysql://" + hostname + ":" + port + "/" + dbName + "?user=" + userName + "&password=" + password;
        con = (Connection) DriverManager.getConnection(jdbcUrl);
    }
    public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
        final int keySize = 2048;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);      
        return keyPairGenerator.genKeyPair();
    }
    KeyPair add() throws Exception
    {
        Statement st=con.createStatement();
        ResultSet rs=st.executeQuery("SELECT userid from users where userid=\""+name+"\"");
        if(rs.next())
        {
            JOptionPane.showMessageDialog(new JFrame(), "Name Already Taken!");
            return null;
        }
        else
        {
            KeyPair keyPair = buildKeyPair();
            PublicKey pubKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            String pubkey=Base64.getEncoder().encodeToString(pubKey.getEncoded());
            int m=st.executeUpdate("INSERT into users(userid,ip,pubkey) VALUES(\""+name+"\",\""+ip+"\",\""+pubkey+"\")");
            if(m==0)
            {
                JOptionPane.showMessageDialog(new JFrame(),"Server Full, Try Again Later!");
                return null;
            }
            else
            {
                System.out.println("User Added");
                con.close();
                return keyPair;
            }
        }
    }
}
