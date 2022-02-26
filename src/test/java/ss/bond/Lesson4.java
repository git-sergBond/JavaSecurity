package ss.bond;

import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Lesson4 {

    @Test
    public void mac() throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");

        byte[] keyBytes = new byte[] {0,1,2,3,4,5,6,7,8 ,9,10,11,12,13,14,15};
        SecretKeySpec key = new SecretKeySpec(keyBytes, "RawBytes");

        mac.init(key);

        byte[] dataBytes1 = "qwertyasdfgh12345".getBytes(StandardCharsets.UTF_8);
        byte[] dataBytes2 = "asdasdgfgfgfgfgfg".getBytes(StandardCharsets.UTF_8);

        mac.update(dataBytes1);
        byte[] macBytes = mac.doFinal(dataBytes2);

        assert macBytes != null;
    }
}
