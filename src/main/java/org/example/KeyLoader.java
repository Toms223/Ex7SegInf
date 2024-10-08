package org.example;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class KeyLoader {
    KeyStore keyStore;
    PrivateKey privateKey;
    public KeyLoader(String keyStorePath, String keyStorePassword) {
        try{
            this.keyStore = KeyStore.getInstance("PKCS12");
            this.keyStore.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());
            String alias = keyStore.aliases().nextElement();
            this.privateKey = (PrivateKey) keyStore.getKey(alias, keyStorePassword.toCharArray());
        } catch (KeyStoreException | UnrecoverableKeyException | CertificateException | IOException | NoSuchAlgorithmException e) {
            System.err.println("KeyStore could not be created");
        }
    }
    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }
}
