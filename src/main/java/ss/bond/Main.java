package ss.bond;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class Main {

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            String cipherAlgorithm = "AES";
            String cipherMode = "CBC";
            String cipherPadding = "PKCS5Padding";
            String cipherTransformation = String.join("/", cipherAlgorithm, cipherMode, cipherPadding);
            Cipher cipher = Cipher.getInstance(cipherTransformation);
            System.out.println("cipher(" + cipherTransformation +") success");

            byte[] keyBytes = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
            String keyAlgorithm = "RawBytes";
            SecretKeySpec key = new SecretKeySpec(keyBytes, keyAlgorithm);
            System.out.println("key(" + keyAlgorithm +") success");
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        System.out.println("test");
    }
}
