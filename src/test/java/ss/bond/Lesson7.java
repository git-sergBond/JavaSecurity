package ss.bond;

import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
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

    @Test
    public void loadKey() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        char[] keyStorePassword = "123abc".toCharArray();
        keyStore.load(null, keyStorePassword);

        char[] keyPassword = "qwerty".toCharArray();
        KeyStore.PasswordProtection entryPassword = new KeyStore.PasswordProtection(keyPassword);

        KeyStore.Entry keyEntry = keyStore.getEntry("keyAlias", entryPassword); // NULL
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("keyAlias", entryPassword); // NULL
        //TODO рассмотреть методы PrivateKeyEntry, Entry, SecretKeyEntry
    }

    @Test
    public void saveKey() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        char[] keyStorePassword = "123abc".toCharArray();
        keyStore.load(null, keyStorePassword);

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);

        KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection("superSecurePassword".toCharArray());
        keyStore.setEntry("superSecretKey", secretKeyEntry, passwordProtection);
    }
}
