import org.example.CertificateVerifier;
import org.example.KeyLoader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class KeyLoaderAndVerifyTests {
    @Test
    public void testCertificateVerifier() {
        CertificateVerifier certificateVerifier = new CertificateVerifier("./end-entities/Alice_1.cer");
        Assertions.assertNotNull(certificateVerifier.getPublicKey());
    }

    @Test
    public void testKeyLoader() {
        KeyLoader keyLoader = new KeyLoader("./pfx/Alice_1.pfx","changeit");
        Assertions.assertNotNull(keyLoader.getPrivateKey());
    }
}
