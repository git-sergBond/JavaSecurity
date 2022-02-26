package ss.bond;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.SecureRandom;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.SignatureException;

public class Lesson5 {

    @Test
    public void signature() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256WithDSA");

        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        signature.initSign(keyPair.getPrivate(), secureRandom);

        byte[] data = "1234567890".getBytes(StandardCharsets.UTF_8);
        signature.update(data);

        byte[] digitalSignature = signature.sign();

        assert digitalSignature != null;
    }
}
