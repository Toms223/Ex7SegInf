package org.example;

import javax.crypto.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;
import java.util.Base64.Encoder;

public class Encryptor {
    File encryptedFile;
    File unencryptedFile;
    File encryptedKeyFile;
    Key key;
    PublicKey publicKey;
    Cipher symmetricCipher;
    Cipher asymmetricCipher;
    Encoder encoder = Base64.getEncoder();
    public Encryptor(String encryptedFileName, String unencryptedFileName, String symmetricAlgorithm, String asymmetricAlgorithm, PublicKey publicKey) {
        try{
            Path encryptedDirectory = Paths.get("./encrypted/");
            if(Files.notExists(encryptedDirectory)) Files.createDirectories(encryptedDirectory);
            this.encryptedFile = new File("./encrypted/" + encryptedFileName);
            this.encryptedKeyFile = new File("./encrypted/" + encryptedFileName.split("\\.")[0] + ".key");
            this.unencryptedFile = new File(unencryptedFileName);
            this.key = KeyGenerator.getInstance(symmetricAlgorithm).generateKey();
            this.publicKey = publicKey;
            this.symmetricCipher = Cipher.getInstance(symmetricAlgorithm);
            this.asymmetricCipher = Cipher.getInstance(asymmetricAlgorithm);
        } catch (IOException e) {
            System.err.println("Error creating encrypted directory");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error creating algorithm: " + e.getMessage());
        } catch (NoSuchPaddingException e) {
            System.err.println("Error creating cipher, required padding: " + e.getMessage());
        }
    }

    public void encrypt() {
        try(
                FileInputStream unencryptedFileStream = new FileInputStream(unencryptedFile);
                FileOutputStream encryptedMessageStream = new FileOutputStream(encryptedFile);
                FileOutputStream encryptedKeyStream = new FileOutputStream(encryptedKeyFile)
        ){
            symmetricCipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] buffer = new byte[1024];
            int bytesRead;
            while((bytesRead = unencryptedFileStream.read(buffer)) != -1){
                symmetricCipher.update(buffer,0,bytesRead);
            }
            byte[] encryptedMessage = symmetricCipher.doFinal();
            asymmetricCipher.init(Cipher.WRAP_MODE, publicKey);
            byte[] encryptedKey = asymmetricCipher.doFinal(key.getEncoded());

            byte[] encryptedBase64Message = encoder.encode(encryptedMessage);
            byte[] encryptedBase64Key = encoder.encode(encryptedKey);
            encryptedKeyStream.write(encryptedBase64Key);
            encryptedMessageStream.write(encryptedBase64Message);

        } catch (IOException e) {
            System.err.println("Error opening unencrypted file");
        } catch (InvalidKeyException e) {
            System.err.println("Error invalid symmetric key");
        } catch (IllegalBlockSizeException e) {
            System.err.println("Error invalid block size");
        } catch (BadPaddingException e) {
            System.err.println("Error invalid padding size");
        }
    }
}
