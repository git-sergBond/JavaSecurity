package ss.bond;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class Main {

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        Cipher cipher = null;
        try {
            String cipherAlgorithm = "AES";
            String cipherMode = "CBC";
            String cipherPadding = "PKCS5Padding";
            String cipherTransformation = String.join("/", cipherAlgorithm, cipherMode, cipherPadding);
            cipher = Cipher.getInstance(cipherTransformation);
            System.out.println("cipher(" + cipherTransformation +") success");
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        byte[] keyBytes = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        String keyAlgorithm = "RawBytes";
        SecretKeySpec key = new SecretKeySpec(keyBytes, keyAlgorithm);
        System.out.println("key(" + keyAlgorithm +") success");

        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            System.out.println("cipher initialised");
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        byte[] plainText = "it is my secret".getBytes(StandardCharsets.UTF_8);
        try {
            byte[] cipherText = cipher.doFinal(plainText);
            System.out.println("cipherText=" + new String(cipherText, StandardCharsets.UTF_8));
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        System.out.println("test");
    }
}
