/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author asus
 */
import com.mysql.jdbc.Connection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.swing.*;
public class ClientHandler extends javax.swing.JFrame implements Runnable{

    /**
     * Creates new form ClientHandler
     */
    int pressed;
    Socket socket;
    DataInputStream dis;
    DataOutputStream dos;
    public Thread t;
    private String name;
    private String nameOther;
    private String tech;
    private JFrame current;
    private String key;
    private PrivateKey privateKeyRSA;
    private KeyPair keyPair;
    private PublicKey publicKeyRSA;
    private String oppPublicKeyRSA;
    public ClientHandler(Socket socket,String name,String tech,String key,KeyPair keyPair) throws IOException {
        initComponents();
        fileChooser.setVisible(false);
        this.privateKeyRSA=keyPair.getPrivate();
        this.publicKeyRSA=keyPair.getPublic();
        this.name=name;
        this.tech=tech;
        current=this;
        this.key=key;
        this.socket=socket;
        dis=new DataInputStream(socket.getInputStream());
        dos=new DataOutputStream(socket.getOutputStream());
        pressed=0;
        System.out.println("ClientHandler Initialised");
        t=new Thread(this,"Client Handler");
        this.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                try
                {
                    Class.forName("com.mysql.jdbc.Driver");
                    String dbName = "cryptchat";
                    String userName = "root";
                    String password = "pass";
                    String hostname = serverIP.IP;
                    String port = "3306";
                    String jdbcUrl = "jdbc:mysql://" + hostname + ":" + port + "/" + dbName + "?user=" + userName + "&password=" + password;
                    Connection con = (Connection) DriverManager.getConnection(jdbcUrl);
                    Statement st=con.createStatement();
                    st.executeUpdate("DELETE from users where userid=\""+name+"\"");
                }
                catch(Exception E)
                {
                    System.out.println("Next level LOL "+E.toString());
                }
            }
        });
    }
    private class clickListener implements ActionListener
    {
        public void actionPerformed(ActionEvent e)
        {
            if(e.getSource()==send)
            {
                pressed=1;
            }
        }
    }
    public static byte[] encrypt(PrivateKey key, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");  
        cipher.init(Cipher.ENCRYPT_MODE, key);  

        return cipher.doFinal(Base64.getDecoder().decode(message));  
    }
    String addSignature(String msg) throws Exception
    {
        try { 
            MessageDigest md = MessageDigest.getInstance("MD5"); 
            byte[] messageDigest = md.digest(Base64.getDecoder().decode(msg)); 
            BigInteger no = new BigInteger(1, messageDigest); 
            String hashtext = no.toString(16); 
            while (hashtext.length() < 32) { 
                hashtext = "0" + hashtext; 
            }
            String encrypted=Base64.getEncoder().encodeToString(encrypt(privateKeyRSA,hashtext));
            System.out.println("Encrypted Hash Sent: "+encrypted);
            System.out.println("Hash Generated: "+hashtext);
            System.out.println("Signed Message: "+encrypted+msg);
            System.out.println(encrypted.length());
            return (encrypted+msg); 
        }  
        catch (NoSuchAlgorithmException e) { 
            throw new RuntimeException(e); 
        }
    }
    public static PublicKey getPublicKey(String base64PublicKey){
        PublicKey publicKey = null;
        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey));
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
    
    public static byte[] decrypt(String key, byte [] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.DECRYPT_MODE, getPublicKey(key));
        System.out.println("werwER");
        return cipher.doFinal(encrypted);
    }
    boolean verifySignature(String cipher) throws Exception
    {
        String sig=cipher.substring(0,344);
        String msg=cipher.substring(344);
        System.out.println("Signature: "+sig);
        String hashReceived=Base64.getEncoder().encodeToString(decrypt(oppPublicKeyRSA,Base64.getDecoder().decode(sig)));
        MessageDigest md = MessageDigest.getInstance("MD5"); 
        byte[] messageDigest = md.digest(Base64.getDecoder().decode(msg)); 
        BigInteger no = new BigInteger(1, messageDigest); 
        String hashtext = no.toString(16); 
        while (hashtext.length() < 32) { 
            hashtext = "0" + hashtext; 
        }
        System.out.println("Received Hash: "+hashReceived);
        System.out.println("Hash Generated: "+hashtext);
        if(hashtext.equals(hashReceived))
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    @Override
    public void run()
    {
        System.out.println("Client handler thread started");
        Thread sendt=new Thread(){
          @Override
          public void run()
            {
                try
                {
                    dos.writeUTF(name);
                    while(true)
                    {
                        clickListener click=new clickListener();
                        send.addActionListener(click);
                        if(pressed==1)
                        {
                            pressed=0;
                            String temp=type.getText();
                            if(temp.length()==0)
                            {
                                continue;
                            }
                            type.setText("");
                            String cipher;
                            System.out.println("Plaintext: "+temp);
                            if(tech.equals("AES"))
                            {
                                cipher=AES.encrypt(temp,key);
                            }
                            else
                            {
                                cipher=DES.encrypt(temp,key);
                            }
                            System.out.println("Cipher Text: "+cipher);
                            dos.writeUTF(addSignature(cipher));
                            SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");  
                            Date date = new Date();
                            if(temp.length()>=10&&temp.substring(0,10).equals("*#%FILE%#*"))
                            {
                                chat.setText(chat.getText()+"\n"+formatter.format(date)+" : "+name+" :: Sending File.");
                            }
                            else
                            {
                                chat.setText(chat.getText()+"\n"+formatter.format(date)+" : "+name+" :: "+temp);
                            }
                        }
                       send.removeActionListener(click);
                    }
                }
                catch(Exception E)
                {
                    System.out.println(E.toString());
                }
            }
        };
        sendt.start();
        Thread receivet=new Thread(){
          @Override
          public void run()
            {
                try
                {
                    nameOther=dis.readUTF();
                    Class.forName("com.mysql.jdbc.Driver");
                    String dbName = "cryptchat";
                    String userName = "root";
                    String password = "pass";
                    String hostname = serverIP.IP;
                    String port = "3306";
                    String jdbcUrl = "jdbc:mysql://" + hostname + ":" + port + "/" + dbName + "?user=" + userName + "&password=" + password;
                    Connection con = (Connection) DriverManager.getConnection(jdbcUrl);
                    Statement st=con.createStatement();
                    ResultSet rs=st.executeQuery("SELECT * from users where userid=\""+nameOther+"\"");
                    rs.next();
                    oppPublicKeyRSA=rs.getString(3);
                    con.close();
                    current.setTitle(name+"-"+nameOther+" -- CryptChat");
                    while(true)
                    {
                        String s;
                        s = dis.readUTF();
                        if(verifySignature(s))
                        {
                            System.out.println("Signature Verified");
                            s=s.substring(344);
                            System.out.println("Cipher: "+s);
                            if(tech.equals("AES"))
                            {
                                String plain=AES.decrypt(s,key);
                                s=plain;
                            }
                            else
                            {
                                String plain=DES.decrypt(s,key);
                                s=plain;
                            }
                            System.out.println("Plaintext: "+s);
                            if(s.equals("*#%EXIT%#*"))
                            {
                                current.dispose();
                                break;
                            }
                            else if(s.length()>=10&&s.substring(0,10).equals("*#%FILE%#*"))
                            {
                                s=s.substring(10);
                                String name=s.substring(0,s.indexOf('*'));
                                receiveFile(name,s.substring(name.length()+1));
                                continue;
                            }
                            SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");  
                            Date date = new Date();
                            chat.setText(chat.getText()+"\n"+formatter.format(date)+" : "+nameOther+" :: "+s);
                        }
                        else
                        {
                            JOptionPane.showMessageDialog(new JFrame(), "Digital Signature Could not be verified! Network not secure!");
                            current.dispose();
                            break;
                        }
                    }
                }
                catch(Exception E)
                {
                    System.out.println(E.toString());
                }
            }
        };
        receivet.start();
    }
    void receiveFile(String name,String content) throws IOException
    {
        directoryChooser.setVisible(true);
        int returnVal = directoryChooser.showOpenDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File myFile=directoryChooser.getSelectedFile();
            Files.write(Paths.get(myFile.getPath() + "/" + name), content.getBytes());
            SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");  
            Date date = new Date();
            chat.setText(chat.getText()+"\n"+formatter.format(date)+" : "+nameOther+" :: File Received.");
        } else {
            System.out.println("File access cancelled by user.");
        }
        
    }
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jFileChooser1 = new javax.swing.JFileChooser();
        jFileChooser2 = new javax.swing.JFileChooser();
        jFileChooser3 = new javax.swing.JFileChooser();
        jScrollPane1 = new javax.swing.JScrollPane();
        type = new javax.swing.JTextArea();
        jScrollPane2 = new javax.swing.JScrollPane();
        chat = new javax.swing.JTextArea();
        send = new javax.swing.JButton();
        exit = new javax.swing.JButton();
        chooseFile = new javax.swing.JButton();
        fileChooser = new javax.swing.JFileChooser();
        directoryChooser = new javax.swing.JFileChooser();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        type.setColumns(20);
        type.setRows(5);
        jScrollPane1.setViewportView(type);

        chat.setEditable(false);
        chat.setColumns(20);
        chat.setRows(5);
        jScrollPane2.setViewportView(chat);

        send.setText("Send");

        exit.setText("EXIT");
        exit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exitActionPerformed(evt);
            }
        });

        chooseFile.setText("Send File");
        chooseFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chooseFileActionPerformed(evt);
            }
        });

        directoryChooser.setApproveButtonToolTipText("");
        directoryChooser.setFileSelectionMode(javax.swing.JFileChooser.DIRECTORIES_ONLY);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(chooseFile)
                        .addGap(18, 18, 18)
                        .addComponent(fileChooser, javax.swing.GroupLayout.PREFERRED_SIZE, 32, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(directoryChooser, javax.swing.GroupLayout.PREFERRED_SIZE, 42, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(exit))
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 349, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(send)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addComponent(jScrollPane2))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(exit)
                        .addComponent(chooseFile))
                    .addComponent(fileChooser, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(directoryChooser, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 264, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 39, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(send, javax.swing.GroupLayout.Alignment.TRAILING))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void exitActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_exitActionPerformed
        // TODO add your handling code here:
        type.setText("*#%EXIT%#*");
        pressed=1;
        this.dispose();
    }//GEN-LAST:event_exitActionPerformed

    private void chooseFileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chooseFileActionPerformed
        // TODO add your handling code here:
        fileChooser.setVisible(true);
        FileInputStream fis = null;
        BufferedInputStream bis = null;
        OutputStream os = null;
        int returnVal = fileChooser.showOpenDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            System.out.println("Selected");
            File file = fileChooser.getSelectedFile();
            try {
                String message = new String(Files.readAllBytes(Paths.get(file.getPath())));
                type.setText("*#%FILE%#*"+file.getName()+"*"+message);
                pressed=1;
            } catch (IOException ex) {
                Logger.getLogger(ClientHandler.class.getName()).log(Level.SEVERE, null, ex);
            }
        } else {
            System.out.println("File access cancelled by user.");
        }
        fileChooser.setVisible(false);
    }//GEN-LAST:event_chooseFileActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(ClientHandler.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(ClientHandler.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(ClientHandler.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(ClientHandler.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        /*java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new ClientHandler().setVisible(true);
            }
        });*/
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextArea chat;
    private javax.swing.JButton chooseFile;
    private javax.swing.JFileChooser directoryChooser;
    private javax.swing.JButton exit;
    private javax.swing.JFileChooser fileChooser;
    private javax.swing.JFileChooser jFileChooser1;
    private javax.swing.JFileChooser jFileChooser2;
    private javax.swing.JFileChooser jFileChooser3;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JButton send;
    private javax.swing.JTextArea type;
    // End of variables declaration//GEN-END:variables
}
