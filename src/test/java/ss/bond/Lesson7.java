package ss.bond;

import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class Lesson7 {

    @Test
    public void keyStore() throws KeyStoreException {
        KeyStore keyStore1 = KeyStore.getInstance(KeyStore.getDefaultType());
        System.out.println(keyStore1.getType());//pkcs12

        KeyStore keyStore2 = KeyStore.getInstance("PKCS12");
    }

    @Test
    public void loadKeyStore() throws KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        //TODO create keyStore.ks
        //TODO try load .jks
        char[] keyStorePassword = "123abc".toCharArray();
        try(InputStream keyStoreData = new FileInputStream("keyStore.ks")) {
            keyStore.load(keyStoreData, keyStorePassword);
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void loadKeyStoreByNull() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        char[] keyStorePassword = "123abc".toCharArray();
        keyStore.load(null, keyStorePassword);
    }
}
