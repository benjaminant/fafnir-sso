package dk.acto.fafnir.server.providers;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;

@EnableWebSecurity
@ConditionalOnProperty(name = {"SAML_IDP"})
public class SamlProvider extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        var repo = new InMemoryRelyingPartyRegistrationRepository();

        http.authorizeRequests().anyRequest().authenticated()
                .and().saml2Login().relyingPartyRegistrationRepository(repo);
    }
}
