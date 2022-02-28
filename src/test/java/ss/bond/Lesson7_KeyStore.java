package ss.bond;

import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.function.Consumer;

public class Lesson7_KeyStore {

    @Test
    public void keyStore() throws KeyStoreException {
        //TODO какие еще могут ыть типы хранилищ?
        KeyStore keyStore1 = KeyStore.getInstance(KeyStore.getDefaultType());
        System.out.println(keyStore1.getType());//pkcs12

        KeyStore keyStore2 = KeyStore.getInstance("PKCS12");
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

    /**
     * Просмотр данных через командную строку:
     * keytool -list -storetype JKS -keystore keyStore.ks -storepass 123abc -v
     *
     * Удаление конкретной Entity:
     * keytool -delete -alias supersecretkey -storetype JKS -keystore keyStore.ks -storepass 123abc -v
     *
     * Генерация ключевой пары:
     * keytool -genkeypair -alias keypair2 -dname 'CN=Sergey Bondarenko, OU=ARGO, O=Neoflex, L=Voronesh, ST=Moscow, C=2222' -keystore keyStore.ks -storepass 123abc
     *
     * Просмотр данных ключевой пары:
     * keytool -list -alias keypair2 -storetype JKS -keystore keyStore.ks -storepass 123abc -v
     *
     * Генерация запроса на сертификат:
     * keytool -certreq -alias keypair2 -storetype JKS -keystore keyStore.ks -storepass 123abc -file CN=SergeyBondarenko.certreq
     *
     * TODO issue certificate
     * TODO keytool -importcert -alias testkey -keypass 123456 -storetype JKS -keystore keystore2.jks -file cert.cert -rfc -storepass abcdef
     */
    @Test
    public void saveKey() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();

        storeKeyStore("keyStore.ks", "123abc", (keyStore -> {
            KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);

            KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection("superSecurePassword".toCharArray());
            try {
                keyStore.setEntry("superSecretKey", secretKeyEntry, passwordProtection);
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        }));

        loadKeyStore("keyStore.ks", "123abc", keyStore -> {
            try {
                KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection("superSecurePassword".toCharArray());
                KeyStore.SecretKeyEntry keyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("superSecretKey", passwordProtection);

                assert keyEntry.getSecretKey() != null;
                assert keyEntry.getSecretKey().equals(secretKey);
            } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
                e.printStackTrace();
            }
        });
    }

    private void storeKeyStore(String path, String password, Consumer<KeyStore> storeConsumer) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException{
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        char[] keyStorePassword = password.toCharArray();
        keyStore.load(null, keyStorePassword);

        storeConsumer.accept(keyStore);

        try (FileOutputStream outputStream = new FileOutputStream(path)) {
            keyStore.store(outputStream, keyStorePassword);//TODO что если тут передать отличающийся пароли от keyStorePassword
        }
    }

    private void loadKeyStore(String path, String password, Consumer<KeyStore> storeConsumer) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        //TODO create keyStore.ks
        //TODO try load .jks
        try(InputStream keyStoreData = new FileInputStream(path)) {
            keyStore.load(keyStoreData, password.toCharArray());
        }

        storeConsumer.accept(keyStore);
    }
}
