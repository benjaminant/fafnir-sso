package dk.acto.auth.providers;

import com.google.common.net.UrlEscapers;
import dk.acto.auth.ActoConf;
import dk.acto.auth.TokenFactory;
import dk.acto.auth.model.FafnirUser;
import dk.acto.auth.model.conf.EconomicConf;
import dk.acto.auth.model.conf.FafnirConf;
import dk.acto.auth.providers.credentials.UsernamePassword;
import dk.acto.auth.providers.economic.EconomicCustomer;
import dk.acto.auth.services.ServiceHelper;
import io.vavr.control.Try;
import lombok.AllArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;

@Component
@AllArgsConstructor
@ConditionalOnBean(EconomicConf.class)
public class EconomicCustomerProvider implements RedirectingAuthenticationProvider<UsernamePassword> {
    private final TokenFactory tokenFactory;
    private final RestTemplate restTemplate = new RestTemplate();
    private final EconomicConf economicConf;
//    private final FafnirConf fafnirConf;
    private final HttpHeaders httpHeaders;
    private final Map<String, Locale> localeMap = Map.of(
            "NOK", Locale.forLanguageTag("no-NO"),
            "SEK", Locale.forLanguageTag("sv-SE"),
            "EUR", Locale.forLanguageTag("en-GB")
    );

    @Override
    public String authenticate() {
        return "/economic/login";
    }

    public Optional<String> callback(final UsernamePassword data) {
        var email = data.getUsername();
        var customerNumber = data.getPassword();

        return Try.of(() -> "https://restapi.e-conomic.com/customers/"  + UrlEscapers.urlPathSegmentEscaper().escape(customerNumber))
                        .map(x -> restTemplate.exchange(x, HttpMethod.GET, new HttpEntity<>(httpHeaders), EconomicCustomer.class))
                        .map(HttpEntity::getBody)
                .filter(x -> x.getEmail() != null)
                .filter(x -> x.getEmail().equals(email))
                .map(x -> tokenFactory.generateToken(FafnirUser.builder()
                        .subject(x.getCustomerNumber())
                        .provider("economic")
                        .name(x.getName())
                        .locale(localeMap.getOrDefault(x.getCurrency(), Locale.forLanguageTag("da-DK")))
                                .build()))
                .toJavaOptional();
    }

    private HttpHeaders getHeaders (ActoConf actoConf) {
        var headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.add("X-AppSecretToken", actoConf.getEconomicAppSecretToken());
        headers.add("X-AgreementGrantToken", actoConf.getEconomicAgreementGrantToken());
        return headers;
    }
}
