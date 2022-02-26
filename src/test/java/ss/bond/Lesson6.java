package ss.bond;

import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.Cipher;

import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;


public class Lesson6 {

    @Test
    public void key() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom random = new SecureRandom();
        int keyBitSize = 256; //TODO как понять какие числа сюда нужно писать?
        keyGenerator.init(keyBitSize, random); // Можно переопределить свой рандомайзер
        SecretKey key = keyGenerator.generateKey();
        assert key != null;
    }

    @Test
    public void keyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        int keyBitSize = 2048; //TODO как понять какие числа сюда нужно писать?
        keyGenerator.initialize(keyBitSize); // Можно оставить стандартный рандомайзер
        KeyPair keyPair = keyGenerator.generateKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        assert null != publicKey;
        assert null != privateKey;
    }

    /**
     * http://tutorials.jenkov.com/java-cryptography/keypairgenerator.html
     * The most commonly known type of asymmetric key pair is the public key, private key type of key pair.
     * The private key is used to encrypt data, and the public key can be used to decrypt the data again.
     * Actually, you could also encrypt data using the public key and decrypt it using the private key.
     *
     * Закрытый ключ используется для шифрования данных, а открытый ключ — для расшифровки данных.
     * На самом деле, вы также можете зашифровать данные с помощью открытого ключа и расшифровать его с помощью закрытого ключа
     *
     * user A              user B
     * encrypt(private) -> decrypt(public)
     * decrypt(private) <- encrypt(public)
     */
    @Test
    public void interestingFeature() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        //generate key pair
        //TODO Что будет если экземпляр класса подписи будет одного алгоритма, а ключ в другом? DSA/RSA
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        int keyBitSize = 2048;
        keyGenerator.initialize(keyBitSize);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        //encrypt(private)
        byte[] data1 = "1234567890".getBytes(StandardCharsets.UTF_8);
        byte[] cipher1 = encrypt(data1, privateKey);
        assert cipher1 != null;

        //decrypt(public)
        byte[] data2 = decrypt(cipher1, publicKey);
        assert data2 != null;
        assert Arrays.equals(data2, data1);

        //encrypt(public)
        byte[] data3 = encrypt(data2, publicKey);
        assert data3 != null;

        /**
         * TODO разобрать почему на этом шаге происходит ошибка
         * javax.crypto.BadPaddingException: Decryption error
         *
         * 	at java.base/sun.security.rsa.RSAPadding.unpadV15(RSAPadding.java:369)
         * 	at java.base/sun.security.rsa.RSAPadding.unpad(RSAPadding.java:282)
         * 	at java.base/com.sun.crypto.provider.RSACipher.doFinal(RSACipher.java:371)
         * 	at java.base/com.sun.crypto.provider.RSACipher.engineDoFinal(RSACipher.java:405)
         * 	at java.base/javax.crypto.Cipher.doFinal(Cipher.java:2202)
         */
        //decrypt(private)
   //     byte[] data4 = decrypt(data2, privateKey);
   //     assert data4 != null;
    }

    private byte[] encrypt(byte[] data, Key key) throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA"); //TODO Что будет если экземпляр класса подписи будет одного алгоритма, а ключ в другом? DSA/RSA
        cipher.init(Cipher.ENCRYPT_MODE, key); // TODO какие еще есть режимы?
        return cipher.doFinal(data);
    }

    private byte[] decrypt(byte[] data, Key key) throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA"); //TODO Что будет если экземпляр класса подписи будет одного алгоритма, а ключ в другом? DSA/RSA
        cipher.init(Cipher.DECRYPT_MODE, key); // TODO какие еще есть режимы?
        return cipher.doFinal(data);
    }
}
