package ss.bond;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class Lesson2 {

    @Test
    public void cipher() {
        Security.addProvider(new BouncyCastleProvider());

        Cipher cipher1, cipher2;
        try {
            /**
             * Режимы ширфования:
             * EBC - Electronic Codebook (Режим электронной кодовой книги)
             * https://ru.wikipedia.org/wiki/%D0%A0%D0%B5%D0%B6%D0%B8%D0%BC_%D1%8D%D0%BB%D0%B5%D0%BA%D1%82%D1%80%D0%BE%D0%BD%D0%BD%D0%BE%D0%B9_%D0%BA%D0%BE%D0%B4%D0%BE%D0%B2%D0%BE%D0%B9_%D0%BA%D0%BD%D0%B8%D0%B3%D0%B8
             *
             * CBC - Cipher Block Chaining (Режим сципления блоков ширфотекста)
             * https://ru.wikipedia.org/wiki/%D0%A0%D0%B5%D0%B6%D0%B8%D0%BC_%D1%81%D1%86%D0%B5%D0%BF%D0%BB%D0%B5%D0%BD%D0%B8%D1%8F_%D0%B1%D0%BB%D0%BE%D0%BA%D0%BE%D0%B2_%D1%88%D0%B8%D1%84%D1%80%D0%BE%D1%82%D0%B5%D0%BA%D1%81%D1%82%D0%B0
             *
             * CFB - Cipher Feedback (Режим обратной связи по шифротексту)
             * https://ru.wikipedia.org/wiki/%D0%A0%D0%B5%D0%B6%D0%B8%D0%BC_%D0%BE%D0%B1%D1%80%D0%B0%D1%82%D0%BD%D0%BE%D0%B9_%D1%81%D0%B2%D1%8F%D0%B7%D0%B8_%D0%BF%D0%BE_%D1%88%D0%B8%D1%84%D1%80%D0%BE%D1%82%D0%B5%D0%BA%D1%81%D1%82%D1%83
             *
             * OFB - Output Feedback (Режим обратной связи по выходу)
             * https://ru.wikipedia.org/wiki/%D0%A0%D0%B5%D0%B6%D0%B8%D0%BC_%D0%BE%D0%B1%D1%80%D0%B0%D1%82%D0%BD%D0%BE%D0%B9_%D1%81%D0%B2%D1%8F%D0%B7%D0%B8_%D0%BF%D0%BE_%D0%B2%D1%8B%D1%85%D0%BE%D0%B4%D1%83
             *
             * CTR - Counter (Режим счетчика)
             * https://ru.wikipedia.org/wiki/%D0%A0%D0%B5%D0%B6%D0%B8%D0%BC_%D1%88%D0%B8%D1%84%D1%80%D0%BE%D0%B2%D0%B0%D0%BD%D0%B8%D1%8F#Counter_mode_%28CTR%29
             */
            cipher1 = Cipher.getInstance("AES");
            cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");

            Key key = new SecretKeySpec(new byte[] {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}, "RawBytes");

            cipher1.init(Cipher.ENCRYPT_MODE, key);

            cipher1.init(Cipher.DECRYPT_MODE, key);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }
}
