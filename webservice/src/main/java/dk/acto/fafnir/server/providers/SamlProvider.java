package dk.acto.fafnir.server.providers;

import dk.acto.fafnir.server.CertificateUtil;
import dk.acto.fafnir.server.TokenFactory;
import io.vavr.control.Try;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@EnableWebSecurity
public class SamlProvider extends WebSecurityConfigurerAdapter {
    private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----\n";
    private static final String END_CERT = "-----END CERTIFICATE-----";
    private final TokenFactory tokenFactory;
    private final X509Certificate spCert;

    public SamlProvider(TokenFactory tokenFactory) {
        this.tokenFactory = tokenFactory;
        this.spCert = Try.of(() -> CertificateUtil.generateSelfSignedX509Certificate(tokenFactory.getKeys())).get();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Taken from SimpleSaml's IdP metadata
        var encVerCertString = "MIIDXTCCAkWgAwIBAgIJALmVVuDWu4NYMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTYxMjMxMTQzNDQ3WhcNNDgwNjI1MTQzNDQ3WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzUCFozgNb1h1M0jzNRSCjhOBnR+uVbVpaWfXYIR+AhWDdEe5ryY+CgavOg8bfLybyzFdehlYdDRgkedEB/GjG8aJw06l0qF4jDOAw0kEygWCu2mcH7XOxRt+YAH3TVHa/Hu1W3WjzkobqqqLQ8gkKWWM27fOgAZ6GieaJBN6VBSMMcPey3HWLBmc+TYJmv1dbaO2jHhKh8pfKw0W12VM8P1PIO8gv4Phu/uuJYieBWKixBEyy0lHjyixYFCR12xdh4CA47q958ZRGnnDUGFVE1QhgRacJCOZ9bd5t9mr8KLaVBYTCJo5ERE8jymab5dPqe5qKfJsCZiqWglbjUo9twIDAQABo1AwTjAdBgNVHQ4EFgQUxpuwcs/CYQOyui+r1G+3KxBNhxkwHwYDVR0jBBgwFoAUxpuwcs/CYQOyui+r1G+3KxBNhxkwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAAiWUKs/2x/viNCKi3Y6blEuCtAGhzOOZ9EjrvJ8+COH3Rag3tVBWrcBZ3/uhhPq5gy9lqw4OkvEws99/5jFsX1FJ6MKBgqfuy7yh5s1YfM0ANHYczMmYpZeAcQf2CGAaVfwTTfSlzNLsF2lW/ly7yapFzlYSJLGoVE+OHEu8g5SlNACUEfkXw+5Eghh+KzlIN7R6Q7r2ixWNFBC/jWf7NKUfJyX8qIG5md1YUeT6GBW9Bm2/1/RiO24JTaYlfLdKK9TYb8sG5B+OLab2DImG99CJ25RkAcSobWNF5zD0O6lgOo3cEdB/ksCq3hmtlC/DlLZ/D8CJ+7VuZnS1rR2naQ==\n";
        var encVerCert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream((BEGIN_CERT + encVerCertString + END_CERT).getBytes()));

        var encVerCred = new Saml2X509Credential(encVerCert,
                Saml2X509Credential.Saml2X509CredentialType.VERIFICATION,
                Saml2X509Credential.Saml2X509CredentialType.ENCRYPTION);

        var decSignCred = new Saml2X509Credential(tokenFactory.getPrivateKey(), spCert,
                Saml2X509Credential.Saml2X509CredentialType.DECRYPTION,
                Saml2X509Credential.Saml2X509CredentialType.SIGNING);

        var reg = RelyingPartyRegistration
                .withRegistrationId("simplesaml")
                .signingX509Credentials(x -> x.add(decSignCred))
                .decryptionX509Credentials(x -> x.add(decSignCred))
                .assertingPartyDetails(x -> x.entityId("http://localhost:8081/simplesaml/saml2/idp/SSOService.php")
                        .encryptionX509Credentials(credentials -> credentials.add(encVerCred))
                        .verificationX509Credentials(credentials -> credentials.add(encVerCred))
                        .singleSignOnServiceLocation("http://localhost:8081/simplesaml/saml2/idp/SSOService.php"))
                .build();

        var repo = new InMemoryRelyingPartyRegistrationRepository(reg);

        http.authorizeRequests().anyRequest().authenticated()
                .and().saml2Login().relyingPartyRegistrationRepository(repo);
    }
}
