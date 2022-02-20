package ss.bond;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.SecureRandom;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;

public class Main {

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        //KeyPair
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        if (Objects.isNull(keyPairGenerator)) {
            System.err.println("keyPairGenerator is NULL");
            return;
        }
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        System.out.println("public: " + keyPair.getPublic());
        System.out.println("private: " + Arrays.toString(keyPair.getPrivate().getEncoded()));

        //Digest
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        if (Objects.isNull(messageDigest)) {
            System.err.println("messageDigest is NULL");
            return;
        }
        byte[] data1 = "ABCDE".getBytes(StandardCharsets.UTF_8);
        byte[] data2 = "12345".getBytes(StandardCharsets.UTF_8);
        messageDigest.update(data1);
        messageDigest.update(data2);
        byte[] digest = messageDigest.digest();
        System.out.println("digest: " + Arrays.toString(digest));

        //MAC (HMAC)
        //TODO как правильно передать секретный ключ, для HMAC ?
        Mac mac = null;
        try {
            mac = Mac.getInstance("HmacSHA256");
        }catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        if (Objects.isNull(mac)) {
            System.err.println("messageDigest is NULL");
            return;
        }
        SecretKeySpec key = getSecretKeySpec();
        try {
            mac.init(key);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        mac.update(data1);
        mac.update(data1);
        byte[] macBytes = mac.doFinal();
        System.out.println("MAC: " + Arrays.toString(macBytes));

        System.out.println("test");
    }

    private static void encryptExample() {
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

        SecretKeySpec key = getSecretKeySpec();

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
    }

    private static SecretKeySpec getSecretKeySpec() {
        byte[] keyBytes = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        String keyAlgorithm = "RawBytes";
        SecretKeySpec key = new SecretKeySpec(keyBytes, keyAlgorithm);
        System.out.println("key(" + keyAlgorithm +") success");
        return key;
    }
}
