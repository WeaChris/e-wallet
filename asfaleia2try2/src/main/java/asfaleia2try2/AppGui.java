
package asfaleia2try2;

import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;


public class AppGui implements ActionListener{
    JFrame frame1;
    BoxLayout panelLayout, frameLayout, panel2Layout, panel3Layout, panel4Layout, panel5Layout, panel6Layout;
    JButton q1, q2, signIn, signUp, newCredit, printCredit, changeCredit, deleteCredit, addCredit, searchForCredit;
    JPanel panel, panel2, panel3, panel4, panel5, panel6;
    //SIGN IN OR SIGN UP FRAMES
    JTextField signin_username = new JTextField();
    JTextField signin_password = new JTextField();
    JTextField signup_name = new JTextField();
    JTextField signup_lastname = new JTextField();
    JTextField signup_email = new JTextField();
    JTextField signup_username = new JTextField();
    JTextField signup_password = new JTextField();
    //NEW CARD FRAME
    JTextField card_type = new JTextField();
    JTextField card_number = new JTextField();
    JTextField card_owner = new JTextField();
    JTextField card_date = new JTextField();
    JTextField card_cvv = new JTextField();
    //PRINT CARD FRAME
    JTextField card_type2 = new JTextField();
    
    int i=0;
    byte[] salt;
    
    public AppGui() throws IOException{
        signinOrsignup();
        
    }
    
    public void signinOrsignup(){
        frame1 = new JFrame("SIGN IN OR SIGN UP");
        panel = new JPanel();
        
        frame1.setLayout(new FlowLayout());
        panelLayout = new BoxLayout(panel,BoxLayout.Y_AXIS);
        panel.setLayout(panelLayout);
        
        q1 =new JButton("SING IN");
        q2 =new JButton("SING UP");
        q1.addActionListener(this);
        q2.addActionListener(this);
        
        panel.add(new JLabel("Καλως ηρθατε στο ηλεκτρονικο WALLET"));
        panel.add(q1);
        panel.add(new JLabel("OR"));
        panel.add(q2);
        
        frame1.add(panel);
        frame1.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame1.setLocationRelativeTo(null);
        frame1.setVisible(true);
        frame1.pack();
    }
    
    public void signIn(){ 
        panel2 = new JPanel();
        panel2Layout = new BoxLayout(panel2, BoxLayout.Y_AXIS);
        panel2.setLayout(panel2Layout);
        
        signIn = new JButton("SIGN IN");
        signIn.addActionListener(this);
        
        panel2.add(new JLabel("PROCCEED TO SIGN IN : "));
        panel2.add(new JLabel("username"));
        panel2.add(signin_username);
        panel2.add(new JLabel("password"));
        panel2.add(signin_password);
        panel2.add(signIn);
        
        frame1.add(panel2);
        frame1.revalidate();
        frame1.validate();
        frame1.repaint();
        frame1.pack();
        
    }
    
    public void signUp(){
        panel2 = new JPanel();
        panel2Layout = new BoxLayout(panel2, BoxLayout.Y_AXIS);
        panel2.setLayout(panel2Layout);
        
        signUp = new JButton("SIGN UP");
        signUp.addActionListener(this);
        
        panel2.add(new JLabel("PROCCEED TO SIGN UP : "));
        
        panel2.add(new JLabel("name"));
        panel2.add(signup_name);
        panel2.add(new JLabel("last name"));
        panel2.add(signup_lastname);
        panel2.add(new JLabel("e-mail"));
        panel2.add(signup_email);
        panel2.add(new JLabel("username"));
        panel2.add(signup_username);
        panel2.add(new JLabel("password"));
        panel2.add(signup_password);
        panel2.add(signUp);
        
        frame1.add(panel2);
        frame1.revalidate();
        frame1.validate();
        frame1.repaint();
        frame1.pack();
    }
    
    public void mainMenu(){
        frame1 = new JFrame();
        frame1.setLayout(new FlowLayout());
        panel2 = new JPanel();
        panel2Layout = new BoxLayout(panel2, BoxLayout.Y_AXIS);
        panel2.setLayout(panel2Layout);
        
        newCredit= new JButton("CREATE A NEW CARD");
        newCredit.addActionListener(this);
        printCredit= new JButton("PRINT A CARD");
        printCredit.addActionListener(this);
        changeCredit= new JButton("CHANGE A CARD");
        changeCredit.addActionListener(this);
        deleteCredit= new JButton("DELETE A CARD");
        deleteCredit.addActionListener(this);
        
        
        panel2.add(new JLabel("WELCOME TO YOUR E-WALLET, PLEASE CHOOSE :"));
        panel2.add(newCredit);
        panel2.add(printCredit);
        panel2.add(changeCredit);
        panel2.add(deleteCredit);
        
        frame1.add(panel2);
        frame1.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame1.setLocationRelativeTo(null);
        frame1.setVisible(true);
        frame1.pack();
    }
    
    public void newCreditPanel(){
        panel3 = new JPanel();
        panel3Layout = new BoxLayout(panel3, BoxLayout.Y_AXIS);
        panel3.setLayout(panel3Layout);
        addCredit= new JButton("ADD");
        addCredit.addActionListener(this);
        
        panel3.add(new JLabel("WELCOME TO THE NEW CARD SECTION, PLEASE COMPLETE THE FOLLOWING INFORMATION"));
        panel3.add(new JLabel("card's type :"));
        panel3.add(card_type);
        panel3.add(new JLabel("card's number :"));
        panel3.add(card_number);
        panel3.add(new JLabel("card's owner :"));
        panel3.add(card_owner);
        panel3.add(new JLabel("card's expiration date :"));
        panel3.add(card_date);
        panel3.add(new JLabel("card's validation number (CVV/CVC2) :"));
        panel3.add(card_cvv);
        panel3.add(addCredit);
        
        frame1.add(panel3);
        frame1.revalidate();
        frame1.validate();
        frame1.repaint();
        frame1.pack();
    }
    
    public void printCardPanel(){
        panel3 = new JPanel();
        panel3Layout = new BoxLayout(panel3, BoxLayout.Y_AXIS);
        panel3.setLayout(panel3Layout);
        searchForCredit= new JButton("Search");
        searchForCredit.addActionListener(this);
        
        panel3.add(new JLabel("WELCOME TO THE PRINT CARD SECTION, PLEASE COMPLETE THE FOLLOWING INFORMATION"));
        panel3.add(new JLabel("WHAT TYPE OF CARDS WOULD YOU LIKE TO SEARCH FOR : "));
        panel3.add(new JLabel("card's type :"));
        panel3.add(card_type2);
        panel3.add(searchForCredit);
        
        frame1.add(panel3);
        frame1.revalidate();
        frame1.validate();
        frame1.repaint();
        frame1.pack();
    }
    public void panelForEveryCard(String type, String number, String expdate, String owner, String cvv){
        panel4 = new JPanel();
        panel4Layout = new BoxLayout(panel4, BoxLayout.X_AXIS);
        panel4.setLayout(panel4Layout);
        
        panel5 = new JPanel();
        panel5Layout = new BoxLayout(panel5, BoxLayout.Y_AXIS);
        panel5.setLayout(panel5Layout);
        
        panel6 = new JPanel();
        panel6Layout = new BoxLayout(panel6, BoxLayout.Y_AXIS);
        panel6.setLayout(panel6Layout);
        
        panel5.add(new JLabel("Type : "));
        panel5.add(new JLabel("Card Number : "));
        panel5.add(new JLabel("Exp Date : "));
        panel5.add(new JLabel("Card Owner : "));
        panel5.add(new JLabel("Card (CVV/CVC2)) : "));
        
        panel6.add(new JLabel(type));
        panel6.add(new JLabel(number));
        panel6.add(new JLabel(expdate));
        panel6.add(new JLabel(owner));
        panel6.add(new JLabel(cvv));
        
        panel4.add(panel5);
        panel4.add(panel6);
        
        frame1.add(panel4);
        frame1.revalidate();
        frame1.validate();
        frame1.repaint();
        frame1.pack();
    }
    
    //SYGKRINEI TA ONOMATA TWN FAKELWN TWN USER ME TO STRING USERNAME OPOY EINAI TO USERNAME POY 8ELEI O KAINOURGIOS XRHSTHS NA XRHSIMOPOIHSEI
    public boolean checkValidUsername(String username) throws FileNotFoundException, IOException{
        String target_dir = "folders";
        File dir = new File(target_dir);
        File[] files = dir.listFiles();
        
        for (File f : files) {
            if(f.isDirectory()) {
                if(f.getName().equals(username)){
                    return false;
                }
            }
        }
        return true;
    }
    //KANEI DECRYPT KAI TOPO9ETEI STA PANEL TIS PLIROFORIES TWN KARTWN POY PROKEITE NA EMFANISTOYN, ME TIN VOEITHEIA THS SEARCHFORYPECARD
    public void getCardsInfoReady() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        FileInputStream readSymmetricKey = new FileInputStream("folders\\"+signin_username.getText()+"\\symetricKey.txt");
        FileInputStream readPrivateKey= new FileInputStream("folders\\"+"privateKey.txt");
        byte[] encryptedSymmetrivKey = readSymmetricKey.readAllBytes();
        byte[] privateKey = readPrivateKey.readAllBytes();
        byte[] symmetricKey= decrypt(encryptedSymmetrivKey, privateKey);
       
        HashMap<Integer, ArrayList<byte[]>> map = searchForTypeCard();
        System.out.println(map);
        for(int i=0; i<map.size(); i++){
            panelForEveryCard(decryptAES(map.get(i).get(0), symmetricKey), decryptAES(map.get(i).get(1), symmetricKey), decryptAES(map.get(i).get(2), symmetricKey), decryptAES(map.get(i).get(3), symmetricKey), decryptAES(map.get(i).get(4), symmetricKey));
        } 
    }
    //H searchForTypeCard PSAXNEI STA DIRACTORIES TOY XRHSTH NA VREI THS PLIROFORIES GIA TIS KARTES POY 8ELEI NA EMFANISEI
    //TIS APO8IKEUEI SE ENA HASHMAP TO OPOIO KAI EPISTREFEI
    public HashMap<Integer, ArrayList<byte[]>> searchForTypeCard() throws FileNotFoundException, IOException{
        HashMap<Integer, ArrayList<byte[]>> map = new HashMap<>();
        ArrayList<byte[]> list;
        String target_dir = "folders\\"+signin_username.getText()+"\\cards";
        File dir = new File(target_dir);
        File[] files = dir.listFiles();
        
        File dir2;
        File[] filesFound =null;
        
        File dir3;
        File[] txtFound =null;
        //ARXIKA PSAXNOYME OLOUS TOYS FAKELOUS(TYPOI KARTWN) GIA NA DOYME AN YPARXEI O TYPOS POY PSAXNOYME
        for (File f : files) {
            if(f.isDirectory()){
                
                if(f.getName().equals(card_type2.getText())){
                    dir2 = new File("folders\\"+signin_username.getText()+"\\cards\\"+card_type2.getText());
                    
                    filesFound = dir2.listFiles();
                }
            }
            
        }
        int i=0;
        
        //TWRA GIA KA8E FAKELO(KARTA) POY YPARXEI MPAINOYME MESA KAI APO8IKEUOYME !!!!!!!!!KA8E TXT SE ENA KELI ENOS ARRAYLIST!!!!!!!!!
        //AFOU OLOKLIRW8OUN TA TXT APO8IKEUOYME TO ARRAYLIST SE ENA HASHMAP ME KWDIKO I OPOU GIA KA8E KARTA EINAI DIAFORETIKO
        //ETSI WSTE KA8E ANTISTOIXIA I ME ARRAYLSIT NA ANTISTOIXEI SE MIA KARTA
        
        for(File f : filesFound){//FOR GIA KATHE KARTA
            if(f.isDirectory()){
                list = new ArrayList<>();
                System.out.println("CREATES TXT");
                String path=f.getPath();
                dir2 = new File(path);
                txtFound = dir2.listFiles();
                for(File f2 : txtFound){ //FOR GIA KATHE TXT KARTAS
                    
                        FileInputStream txtReader = new FileInputStream(f2.getPath());
                        list.add(txtReader.readAllBytes());
                        System.out.println("ADDS TXT");
                    
                }
                System.out.println(list.size());
                map.put(i, list);
                i++;
            }   
        }
        return map;
    }
    //APO8IKEYEI STA KATALILA DIRECTORIES TIS PLHROFORIES THS KARTAS POY EKANE ADD O XRHSTHS  AFOU TIS KANEI ENCRYPT ME TO SYMMETRIKO KLEIDI
    public void saveNewCard() throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        File file1 = new File("folders\\"+signin_username.getText()+"\\cards");
        file1.mkdirs();
        File file2 = new File("folders\\"+signin_username.getText()+"\\cards\\"+card_type.getText());
        file2.mkdirs();
        File file3 = new File("folders\\"+signin_username.getText()+"\\cards\\"+card_type.getText()+"\\"+card_number.getText()+"\\");
        file3.mkdirs();
        FileInputStream readSymmetricKey = new FileInputStream("folders\\"+signin_username.getText()+"\\symetricKey.txt");
        FileInputStream readPrivateKey= new FileInputStream("folders\\"+"privateKey.txt");
        
        FileOutputStream typeW = new FileOutputStream("folders\\"+signin_username.getText()+"\\cards\\"+card_type.getText()+"\\"+card_number.getText()+"\\"+card_type.getText()+".txt");
        FileOutputStream numerW = new FileOutputStream("folders\\"+signin_username.getText()+"\\cards\\"+card_type.getText()+"\\"+card_number.getText()+"\\"+card_number.getText()+".txt");
        FileOutputStream ownerW = new FileOutputStream("folders\\"+signin_username.getText()+"\\cards\\"+card_type.getText()+"\\"+card_number.getText()+"\\"+card_owner.getText()+".txt");
        FileOutputStream dateW = new FileOutputStream("folders\\"+signin_username.getText()+"\\cards\\"+card_type.getText()+"\\"+card_number.getText()+"\\"+card_date.getText()+".txt");
        FileOutputStream cvvW = new FileOutputStream("folders\\"+signin_username.getText()+"\\cards\\"+card_type.getText()+"\\"+card_number.getText()+"\\"+card_cvv.getText()+".txt");
        
        byte[] encryptedSymmetrivKey = readSymmetricKey.readAllBytes();
        byte[] privateKey = readPrivateKey.readAllBytes();
        byte[] symmetricKey= decrypt(encryptedSymmetrivKey, privateKey);
        
        typeW.write(encryptAES(card_type.getText(), symmetricKey));
        numerW.write(encryptAES(card_number.getText(), symmetricKey));
        ownerW.write(encryptAES(card_owner.getText(), symmetricKey));
        dateW.write(encryptAES(card_date.getText(), symmetricKey));
        cvvW.write(encryptAES(card_cvv.getText(), symmetricKey));
    }
    
    //ELENXEI AN TO USERNAME POY EVALE O XRISTIS EINAI VALID H OXI 
    //KAI META FTIAXNEI TO DIRECTORY TO XRHSTH KAI VAZEI MESA OLA TA APARAITITA TXT ARXEIA KRYPTOGRAFONTAS TA DEDOMENA
    public void createDirAndFile() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException{
        if(checkValidUsername(signup_username.getText())){
            //USERNAME SWSTO---->DHLADH DEN YPARXEI, OPOTE PROXWRAW STHN DHMIOYRGIA TOU USER 
            File file1 = new File("folders\\"+signup_username.getText());
            file1.mkdirs();
            
            //ftiaxnw WRITER kai file
            FileOutputStream infoW = new FileOutputStream("folders\\"+signup_username.getText()+"\\info.txt");
            FileOutputStream saltW = new FileOutputStream("folders\\"+signup_username.getText()+"\\salt.txt");
            FileOutputStream symetricKey = new FileOutputStream("folders\\"+signup_username.getText()+"\\symetricKey.txt");
            FileOutputStream passwordW = new FileOutputStream("folders\\"+signup_username.getText()+"\\EncryptedPassword.txt");
            FileOutputStream passwordW2 = new FileOutputStream("folders\\"+signup_username.getText()+"\\HashedPassword.txt");
            FileOutputStream usernameWriter = new FileOutputStream("folders\\usernames.txt");
            //APO8IKEUW TA STOIXEIA TOY USER
            infoW.write(signup_name.getText().getBytes());
            infoW.write("\n".getBytes());
            infoW.write(signup_lastname.getText().getBytes());
            infoW.write("\n".getBytes());
            infoW.write(signup_email.getText().getBytes());
            infoW.write("\n".getBytes());
            infoW.write(signup_username.getText().getBytes());
            //GIA DEBBUGGING LOGOUS APO8IKEUW TO HASHED PASSWORD
            salt=createSalt();
            passwordW2.write(hashingThePassword(signup_password.getText(), salt));
            //APO8IKEUW TO PASSWORD AFOU TO KANW HASH ME TO SALT KAI META ENCRYPT ME TO DIMOSIO KLEIDI
            passwordW.write(encrypt(hashingThePassword(signup_password.getText(), salt), readPublicKey()));
            
            //APO8KEUW TO SALT TOY USER
            saltW.write(salt);
            //APO8IKEUW SYMMETRIKO KLEIDI 
            symetricKey.write(AES_256_symetricKey());
            //APO8IKEUW TO USERNAME TOY NEOY XRHSTH STO TXT ARXEIO OPOY EXEI APOKLEISTIKA TA USERNAME GIA NA KANEI ELENXO 
            usernameWriter.write(signup_username.getText().getBytes());
            usernameWriter.write("\n".getBytes());
        }else{
    
        panel2.add(new JLabel("username invalid"));
                    frame1.revalidate();
                    frame1.validate();
                    frame1.repaint();
                    frame1.pack();
        }
    }
    //KANEI TIN APOKRIPTOGRAFISEI !!AES!! TON BYTE POY THS DINEIS ME TO SYMMETRIKO KLEIDI
    public static String decryptAES(byte[] data, byte[] symmetricKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        SecretKeySpec secretKey= new SecretKeySpec(symmetricKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        
        return new String(cipher.doFinal(data));
    }
    //KANEI TIN KRUPTOGRAFISI !!AES!! TWN BYTE POY TIS DINEIS ME TO SYMMETRIKO KLEIDI
    public static byte[] encryptAES(String data, byte[] symmetricKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
        SecretKeySpec secretKey= new SecretKeySpec(symmetricKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data.getBytes("UTF-8"));
        
    }
    //KANEI TIN KRUPTOGRAFISI !!RSA!! TWN BYTE POY TIS DINEIS ME TO DHMIOSIO KLEIDI
    public static byte[] encrypt(byte[] data, byte[] publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        return cipher.doFinal(data);
    }
    //METATREPEI TA BYTE TO DHMOSIOY KLEIDIOY OPWS TA DIABAZW APO TO TXT SE ANTIKEIMENO PUBLIC KEY
    public static PublicKey getPublicKey(byte[] pk) throws NoSuchAlgorithmException, InvalidKeySpecException{
        PublicKey publicKey = null;
        X509EncodedKeySpec KeySpec = new X509EncodedKeySpec(pk);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        publicKey= keyFactory.generatePublic(KeySpec);
        return publicKey;
    }
    
   //KANEI TIN APOKRUPTOGRAFISI !!RSA!! TWN BYTE POY TIS DINEIS ME TO IDIOTIKO KLEIDI
    public static byte[] decrypt(byte[] data, byte[] privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));
        return cipher.doFinal(data);
    }
    //METATREPEI TA BYTE TO IDIOTIKOY KLEIDIOY OPWS TA DIABAZW APO TO TXT SE ANTIKEIMENO PRIVATE KEY
    public static PrivateKey getPrivateKey(byte[] pk) throws NoSuchAlgorithmException, InvalidKeySpecException{
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pk));
        return privateKey;
    }
    //DIAVAZEI TA BYTE TOY DHMIOSIOY KLEIDIOY
    public byte[] readPublicKey() throws IOException{
        FileInputStream pk = new FileInputStream("folders\\publicKey.txt");
        byte pk2[] =pk.readAllBytes();
        return pk2;
    }
    //FTIAXNEI SALT
    public byte[] createSalt(){
        SecureRandom random = new SecureRandom();
        salt = new byte[16];
        random.nextBytes(salt);
        
        return salt;
    }
    //KANEI HASH ME TO SALT TO STRING POY TIS DINEIS KAI EPISTREFEI TA BYTE
    public byte[] hashingThePassword(String tobeHashed, byte[] salt) throws NoSuchAlgorithmException{
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(salt);
        byte[] hashedPassword = md.digest(tobeHashed.getBytes());
        return hashedPassword;
    }
    
    //KATASKEVAZEI ENA AES 256 SYMMETRIKO KLEIDI KAI TO KANEI ENCRYPT ME TO DIMOSIO KLEIDI
    public byte[] AES_256_symetricKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        Path path = Paths.get("folders\\"+signup_username.getText()+"\\salt.txt");
        byte[] salt = Files.readAllBytes(path);
        
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec("string".toCharArray(), salt, 65536, 256);
        SecretKey secretKey = skf.generateSecret(spec);
        SecretKeySpec key = new SecretKeySpec(secretKey.getEncoded(), "AES");

        return encrypt(key.getEncoded(), readPublicKey());
        
    }
    //SYGKRINEI TA DYO HASHED PASSWORDS
    //ENA AFTO POY EBALE O XRISTIS KAI DYO AFTO POY EXOYME APO8IKEUSEI EMEIS STO ARXEIO TOY XRHSTH 
    public boolean authentication() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        
            System.out.println("TEST1");
            
            
            FileInputStream privateKeyHandler = new FileInputStream("folders\\"+"privateKey.txt");
            
            System.out.println("TEST2");
            FileInputStream saltHandler = new FileInputStream("folders\\"+signin_username.getText()+"\\salt.txt");
            FileInputStream pswHandler = new FileInputStream("folders\\"+signin_username.getText()+"\\EncryptedPassword.txt");
            
            System.out.println("TEST3");
            
            byte[] privateKey = privateKeyHandler.readAllBytes();
            
            //EDW KANW DECRYPT TO APO8IKEUMENO STO TXT PASSWORD WSTE NA PARW TO HASH TOY
            byte[] savedPsw=decrypt(pswHandler.readAllBytes(), privateKey);

            System.out.println("TEST4");
            //EDW KANW HASH TO PASSWORD POY EVALE O XRISTIS ME TO SALT  POY ANTISTOIXEI STO XRHSTH ME VASI TO USERNAME
            byte[] inputPsw=hashingThePassword(signin_password.getText(), saltHandler.readAllBytes());
            
            System.out.println("TEST5");
            //METATREPW TA BYTE SE STRING GIA GINEI H SYGKRISH
            String SsavedPsw = Base64.getEncoder().encodeToString(savedPsw);
            String SinputPsw = Base64.getEncoder().encodeToString(inputPsw);
            
            
            System.out.println(savedPsw);
            System.out.println(inputPsw);
            
            System.out.println(SsavedPsw);
            System.out.println(SinputPsw);
            
            if(SsavedPsw.equals(SinputPsw)){
                return true;
            }else{
                return false;
            }
        
    }
    //ME VASI TA KOYMPIA POY PATIOUNTAI KALW TIS KATALILLES SYNARTHSEIS
    @Override
    public void actionPerformed(ActionEvent e) {
        if(e.getSource()==q1){
            signIn();
        }else if(e.getSource()==q2){
            signUp();
        }else if(e.getSource()==signIn){
            try {
                if(authentication()){
                    mainMenu();
                }else{
                    panel2.add(new JLabel("FAILED TO LOGIN"));
                    frame1.revalidate();
                    frame1.validate();
                    frame1.repaint();
                    frame1.pack();
                }
            } catch (IOException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            }
        }else if(e.getSource()==signUp){
            try {
                try {
                    
                        createDirAndFile();
                    
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchPaddingException ex) {
                    Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IllegalBlockSizeException ex) {
                    Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
                } catch (BadPaddingException ex) {
                    Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidKeyException ex) {
                    Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
                }catch (InvalidKeySpecException ex) {
                        Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
                    }
            } catch (IOException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            }
 
        }else if(e.getSource()==newCredit){
            newCreditPanel();
        }else if(e.getSource()==printCredit){
            printCardPanel();
        }else if(e.getSource()==changeCredit){
            
        }else if(e.getSource()==deleteCredit){
            
        }else if(e.getSource()==addCredit){
            try {
                saveNewCard();
                panel3.add(new JLabel("succeed and now closing..."));
                frame1.revalidate();
                frame1.validate();
                frame1.repaint();
                frame1.pack();
            } catch (IOException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            }
            try {
                Thread.sleep(1000);
            } catch (InterruptedException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            }
            
            frame1.remove(panel3);
            frame1.revalidate();
            frame1.validate();
            frame1.repaint();
            frame1.pack();
            
        }else if(e.getSource()==searchForCredit){
            try {
                getCardsInfoReady();
            } catch (IOException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(AppGui.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
   
    }
}

