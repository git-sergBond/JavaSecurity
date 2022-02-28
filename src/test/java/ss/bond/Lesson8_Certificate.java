package ss.bond;

import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.NoSuchProviderException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertPath;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

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
        System.out.println("===certificate===");
        System.out.println(certificate);
        System.out.println("===getEncoded===");
        System.out.println(Arrays.toString(certificate.getEncoded()));//ASN1 DER
        PublicKey publicKey = certificate.getPublicKey();
        System.out.println("===publicKey===");
        System.out.println(publicKey);
        System.out.println("===getType===");
        System.out.println(certificate.getType());//X.509
        System.out.println("===verify===");
        PublicKey publicKeyFromRootCA = null;//TODO sign Cert by RootCA and getRootCA
        try {
            certificate.verify(publicKeyFromRootCA);
        } catch (InvalidKeyException e) {
            System.err.println("сертификат не был подписан данным открытым ключом");
            e.printStackTrace();
        } catch (NoSuchAlgorithmException |
                NoSuchProviderException |
                SignatureException |
                CertificateException e){
            System.err.println("что-то еще пошло не так");
            e.printStackTrace();
        }


        X509Certificate x509Certificate = (X509Certificate) certificate;//X509Certificate implement Certificate
        //TODO просмотреть методы X509Certificate
    }

    @Test
    public void getCertificateFromCertificateFactory() throws CertificateException, IOException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        try(FileInputStream fileInputStream = new FileInputStream("server.cer")) {
            X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
            System.out.println("===x509Certificate===");
            System.out.println(x509Certificate);
        }
    }

    @Test
    public void certPath() {
        //TODO laod from CertificateFactory или CertPathBuilder
        CertPath certPath = new CertPath("X.509") {
            @Override
            public Iterator<String> getEncodings() {
                return null;
            }

            @Override
            public byte[] getEncoded() throws CertificateEncodingException {
                return new byte[0];
            }

            @Override
            public byte[] getEncoded(String s) throws CertificateEncodingException {
                return new byte[0];
            }

            @Override
            public List<? extends Certificate> getCertificates() {
                return null;
            }
        };
        List<Certificate> certificates = (List<Certificate>) certPath.getCertificates();
        System.out.println(certPath.getType());
        //TODO check CRL, check other methods
        //TODO sign by RootCA and read cert chain and check
    }
}
