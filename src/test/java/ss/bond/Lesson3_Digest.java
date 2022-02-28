package ss.bond;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Lesson3_Digest {

    @Test
    public void digestOneBlock() throws NoSuchAlgorithmException {
        byte[] data1 = "1234".getBytes(StandardCharsets.UTF_8);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] digest = messageDigest.digest(data1);
        
        assert digest != null;
    }

    @Test
    public void digestMoreOneBlock() throws NoSuchAlgorithmException {
        byte[] data1 = "abcd".getBytes(StandardCharsets.UTF_8);
        byte[] data2 = "*-*-".getBytes(StandardCharsets.UTF_8);
        byte[] data3 = "1234".getBytes(StandardCharsets.UTF_8);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(data1);
        messageDigest.update(data2);
        byte[] digest = messageDigest.digest(data3);

        assert digest != null;
    }
}
