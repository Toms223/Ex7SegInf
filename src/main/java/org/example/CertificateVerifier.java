package org.example;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.util.*;

public class CertificateVerifier {
    Path intermediateCertificates = Paths.get("./intermediates");
    Path trustAnchors = Paths.get("./trust-anchors");
    FileInputStream endEntity;
    public CertificateVerifier(String endEntityPath) {
        try {
            this.endEntity = new FileInputStream(endEntityPath);
        } catch (FileNotFoundException e) {
            System.err.println("File not found: " + endEntityPath);
        }

    }

    public PublicKey getPublicKey() {
        try{
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(endEntity);
            if(!verifyCertificate(certificate, cf)) throw new CertificateException("Certificate verification failed");
            return certificate.getPublicKey();
        } catch (CertificateException e) {
            System.err.println(e.getMessage());
            return null;
        }
    }

    private boolean verifyCertificate(X509Certificate certificate, CertificateFactory cf) {
        List<X509Certificate> intermediateCerts = getCertificates(intermediateCertificates, cf);
        intermediateCerts.removeIf(cert -> !certificate.getIssuerX500Principal().equals(cert.getSubjectX500Principal()));
        List<X509Certificate> trustAnchorCerts = getCertificates(trustAnchors, cf);
        List<X509Certificate> certChain = new ArrayList<>();
        certChain.add(certificate);
        certChain.addAll(intermediateCerts);
        try{
            CertPath certPath = cf.generateCertPath(certChain);
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            for (X509Certificate rootCert : trustAnchorCerts) {
                trustAnchors.add(new TrustAnchor(rootCert, null));
            }
            PKIXParameters params = new PKIXParameters(trustAnchors);
            params.setRevocationEnabled(false);
            CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
            certPathValidator.validate(certPath, params);
        } catch (CertificateException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | CertPathValidatorException e) {
            System.err.println(e.getMessage());
            return false;
        }
        return true;
    }

    private List<X509Certificate> getCertificates(Path certificatesPath, CertificateFactory cf) {
        List<X509Certificate> certificates = new ArrayList<>();
        try(DirectoryStream<Path> directoryStream = Files.newDirectoryStream(certificatesPath)){
            for(Path path : directoryStream){
                if(!Files.isRegularFile(path)) continue;
                if(!path.getFileName().toString().endsWith(".cer")) continue;
                FileInputStream intermediateCertFileStream = new FileInputStream(path.toFile());
                try {
                    X509Certificate intermediateCert = (X509Certificate) cf.generateCertificate(intermediateCertFileStream);
                    certificates.add(intermediateCert);
                } catch (CertificateException e) {
                    System.err.println("Certificate exception: " + e.getMessage());
                }
            }
        } catch (IOException  e) {
            return certificates;
        }
        return certificates;
    }
}
