package ss.bond;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Lesson8_Certificate {

    Runtime runtime = Runtime.getRuntime();

    @Test
    public void getCertificateFromKeyStore() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, InterruptedException {

        //TODO implement execCMD in working directory
        //TODO implement this commands with Java code
        //Generate the server certificate.
        //execCMD("keytool -genkey -alias server-alias -keyalg RSA -keypass changeit -dname 'CN=Sergey Bondarenko, OU=rootCA, O=Neoflex, L=Voronesh, ST=Moscow, C=2222' -storepass changeit -keystore keystore.jks");
        //Export the generated server certificate in keystore.jks into the file server.cer.
        //TODO что это значит? execCMD("keytool -export -alias server-alias -storepass changeit -file server.cer -keystore keystore.jks");
        //To add the server certificate to the truststore file, cacerts.jks, run keytool from the directory where you created the keystore and server certificate
        //TODO что это значит? execCMD("keytool -import -trustcacerts -alias server-alias -file server.cer -keystore cacerts.jks -keypass changeit -storepass changeit");

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try(FileInputStream fileInputStream = new FileInputStream("keystore.jks")) {
            keyStore.load(fileInputStream, "changeit".toCharArray());
        }

        Certificate certificate = keyStore.getCertificate("server-alias");

        assert certificate != null;
        System.out.println(certificate.toString());
    }

    @Test
    public void getCertificateFromCertificateFactory() {

    }
}
