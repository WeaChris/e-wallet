
package asfaleia2try2;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;


public class RsaCrypto {
    private PublicKey pub;
    private PrivateKey prv;
    
    public RsaCrypto() throws NoSuchAlgorithmException, IOException{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        pub=kp.getPublic();
        prv=kp.getPrivate();
        
        saveIntoFile();
    }

    public void saveIntoFile() throws IOException{
        
        File file1 = new File("publicKey.txt");
        File file2 = new File("privateKey.txt");

        file1.createNewFile();
        file2.createNewFile();
        
        FileOutputStream writer1 = new FileOutputStream("publicKey.txt");
        FileOutputStream writer2 = new FileOutputStream("privateKey.txt");
        
        writer1.write(pub.getEncoded());
        writer2.write(prv.getEncoded());
    }
}
