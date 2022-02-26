package ss.bond;

import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;


public class Lesson6 {

    @Test
    public void key() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom random = new SecureRandom();
        int keyBitSize = 256; //TODO как понять какие числа сюда нужно писать?
        keyGenerator.init(keyBitSize, random); //TODO если не использовать random то что будет использовано вместо него?
        SecretKey key = keyGenerator.generateKey();
        assert key != null;
    }

    @Test
    public void keyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        int keyBitSize = 2048; //TODO как понять какие числа сюда нужно писать?
        keyGenerator.initialize(keyBitSize); //TODO если не использовать random то что будет использовано вместо него?
        KeyPair keyPair = keyGenerator.generateKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        assert null != publicKey;
        assert null != privateKey;
    }

    /**
     * Закрытый ключ используется для шифрования данных, а открытый ключ — для расшифровки данных.
     * На самом деле, вы также можете зашифровать данные с помощью открытого ключа и расшифровать его с помощью закрытого ключа
     *
     * encrypt(private) -> decrypt(public)
     * decrypt(private) <- encrypt(public)
     */
    @Test
    public void interestingFeature() {

    }
}
