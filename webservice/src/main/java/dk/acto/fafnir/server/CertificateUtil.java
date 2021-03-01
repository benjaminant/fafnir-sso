package dk.acto.fafnir.server;

import com.google.common.base.Strings;
import org.bouncycastle.x509.X509V1CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateUtil {
    public static X509Certificate generateSelfSignedX509Certificate (KeyPair keyPair) throws NoSuchAlgorithmException,
            CertificateEncodingException, NoSuchProviderException, InvalidKeyException, SignatureException {

        // yesterday
        var validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        // in 2 years
        var validityEndDate = new Date(System.currentTimeMillis() + 2L * 365 * 24 * 60 * 60 * 1000);

        var certGen = new X509V1CertificateGenerator();
        X500Principal dnName = new X500Principal("CN=John Doe");

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setSubjectDN(dnName);
        certGen.setIssuerDN(dnName); // use the same
        certGen.setNotBefore(validityBeginDate);
        certGen.setNotAfter(validityEndDate);
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        return certGen.generate(keyPair.getPrivate(), "BC");
    }
}
