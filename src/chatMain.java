
import com.mysql.jdbc.Connection;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import static java.lang.Thread.sleep;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.Statement;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.*;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author asus
 */
public class chatMain extends javax.swing.JFrame {

    /**
     * Creates new form chatMain
     */
    private Vector users=new Vector();
    private int i;
    private String name;
    private JFrame current;
    private Connection con;
    private chat ob;
    private KeyPair keyPair;
    private int threadStarted;
    public chatMain(String name,KeyPair keyPair) throws Exception {
        this.name=name;
        System.out.println("ChatMain Constructor");
        initComponents();
        this.setTitle(name+" - CryptChat");
        aes.setSelected(true);
        i=-1;
        threadStarted=0;
        current=this;
        this.keyPair=keyPair;
        ob=new chat(name,keyPair);
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
                    con = (Connection) DriverManager.getConnection(jdbcUrl);
                    Statement st=con.createStatement();
                    st.executeUpdate("DELETE from users where userid=\""+name+"\"");
                }
                catch(Exception E)
                {
                    System.out.println(E.toString());
                }
            }
        });
    }

    

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroup1 = new javax.swing.ButtonGroup();
        Next = new javax.swing.JButton();
        nextUser = new javax.swing.JTextField();
        chat = new javax.swing.JButton();
        aes = new javax.swing.JRadioButton();
        des = new javax.swing.JRadioButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        Next.setText("Next");
        Next.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                NextActionPerformed(evt);
            }
        });

        nextUser.setEditable(false);

        chat.setText("Communicate");
        chat.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chatActionPerformed(evt);
            }
        });

        buttonGroup1.add(aes);
        aes.setText("AES");

        buttonGroup1.add(des);
        des.setText("DES");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(aes)
                        .addGap(18, 18, 18)
                        .addComponent(des)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(Next))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(nextUser, javax.swing.GroupLayout.PREFERRED_SIZE, 274, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(chat)
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(nextUser, javax.swing.GroupLayout.DEFAULT_SIZE, 44, Short.MAX_VALUE)
                    .addComponent(chat))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(Next)
                    .addComponent(aes)
                    .addComponent(des))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void NextActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_NextActionPerformed
        try {
            // TODO add your handling code here:
            this.display();
        } catch (Exception ex) {
            Logger.getLogger(chatMain.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_NextActionPerformed

    private void chatActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chatActionPerformed
        establishConnection();
    }//GEN-LAST:event_chatActionPerformed
    void establishConnection()
    {
        try {
            // TODO add your handling code here:
            aes.setActionCommand("AES");
            des.setActionCommand("DES");
            String tech=buttonGroup1.getSelection().getActionCommand();
            System.out.println("Technique Selected: "+tech);
            System.out.println("Trying to connect to: "+(String)((Vector)users.get(i)).get(1));
            ob.connect((String)((Vector)users.get(i)).get(1),tech,(String)((Vector)users.get(i)).get(2));
        } catch (Exception ex) {
            Logger.getLogger(chatMain.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
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
            java.util.logging.Logger.getLogger(chatMain.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(chatMain.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(chatMain.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(chatMain.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        //chatMain ob=new chatMain("");
        /*java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                ob.setVisible(true);
            }
        });*/
    }
    void display() throws Exception
    {
        int n=users.size();
        if(n==0)
        {
            JOptionPane.showMessageDialog(new JFrame(),"No other users found, please wait!");
            sleep(10000);
            fetch();
        }
        i++;
        if(i>=n)
        {
            users.clear();
            i=-1;
            this.fetch();
            return;
        }
        System.out.println(i);
        Vector temp=new Vector();
        temp=(Vector)users.get(i);
        String next=(String)temp.get(0);
        nextUser.setText(next);
    }
    void fetch()throws Exception
    {
        if(threadStarted==0)
        {
            threadStarted=1;
            ob.start();
            System.out.println("Socket Opened");
        }
        Class.forName("com.mysql.jdbc.Driver");
        String dbName = "cryptchat";
        String userName = "root";
        String password = "pass";
        String hostname = serverIP.IP;
        String port = "3306";
        String jdbcUrl = "jdbc:mysql://" + hostname + ":" + port + "/" + dbName + "?user=" + userName + "&password=" + password;
        con = (Connection) DriverManager.getConnection(jdbcUrl);
        Statement st=con.createStatement();
        ResultSet rs=st.executeQuery("SELECT * from users where userid!=\""+name+"\"");   
        ResultSetMetaData md=rs.getMetaData();
        int col=md.getColumnCount();
        while(rs.next())
        {
            Vector temp=new Vector();
            for(int i=1;i<=col;i++)
            {
                Object value=rs.getObject(i);
                temp.add(String.valueOf(value));
            }
            users.add(temp);
        }
        this.display();
        con.close();
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton Next;
    private javax.swing.JRadioButton aes;
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.JButton chat;
    private javax.swing.JRadioButton des;
    private javax.swing.JTextField nextUser;
    // End of variables declaration//GEN-END:variables
}
