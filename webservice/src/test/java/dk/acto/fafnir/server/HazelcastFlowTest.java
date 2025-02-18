package dk.acto.fafnir.server;

import dk.acto.fafnir.api.model.FafnirUser;
import dk.acto.fafnir.client.FafnirClient;
import dk.acto.fafnir.client.FafnirClientConfiguration;
import dk.acto.fafnir.client.JwtValidator;
import dk.acto.fafnir.server.model.conf.FafnirConf;
import dk.acto.fafnir.server.provider.HazelcastProvider;
import dk.acto.fafnir.server.provider.credentials.UsernamePasswordCredentials;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@Import(FafnirClientConfiguration.class)
class HazelcastFlowTest {
    private static final Pattern JWT_MATCHER = Pattern.compile("/success#(.+)$");

    @Autowired
    private FafnirClient fafnirClient;

    @Autowired
    private HazelcastProvider hazelcastProvider;

    @Autowired
    private FafnirConf fafnirConf;

    @Autowired
    private JwtValidator jwtValidator;

    @Test
    void testFullSuccessFlow() {
        var me = FafnirUser.builder()
                .subject("om@acto.dk")
                .password("omom")
                .name("Oscar Mike")
                .provider("test")
                .organisationId("acto")
                .organisationName("Acto ApS")
                .metaId("meta")
                .locale(Locale.forLanguageTag("da-DK"))
                .roles(List.of("User", "Admin", "Site God").toArray(String[]::new))
                .created(Instant.MIN)
                .build();
        fafnirClient.exportToFafnir(fafnirClient.toSecureUser(me));
        var result = hazelcastProvider.callback(UsernamePasswordCredentials.builder()
                .username("om@acto.dk")
                .password("omom")
                .build());
        var url = result.getUrl(fafnirConf);
        assertThat(url).contains("/success#");
        var matcher = JWT_MATCHER.matcher(url);
        assertThat(matcher.find()).isTrue();
        var jwt = matcher.group(1);
        var auth = jwtValidator.decodeToken(jwt);
        assertThat(auth.getUsername()).isEqualTo("om@acto.dk");
        assertThat(auth.getName()).isEqualTo("Oscar Mike");
        assertThat(auth.getMetaId()).isEqualTo("meta");
        assertThat(auth.hasMetaId()).isTrue();
        assertThat(auth.getPassword()).isNull();
        assertThat(auth.getDetails().getLocale()).isEqualTo(Locale.forLanguageTag("da-DK"));
        assertThat(auth.getDetails().getOrganisationId()).isEqualTo("acto");
        assertThat(auth.getDetails().getOrganisationName()).isEqualTo("Acto ApS");
        assertThat(auth.getDetails().getRoles()).contains("User", "Admin", "Site God");
        assertThat(auth.getDetails().getCreated()).isNotNull();
        assertThat(auth.getDetails().getCreated()).isNotEqualTo(Instant.MIN);
    }

    @Test
    void testNoSecurityFailsFlow() {
        var me = FafnirUser.builder()
                .subject("om@acto.dk")
                .password("omom")
                .name("Oscar Mike")
                .provider("test")
                .organisationId("acto")
                .organisationName("Acto ApS")
                .metaId("meta")
                .locale(Locale.forLanguageTag("da-DK"))
                .roles(List.of("User", "Admin", "Site God").toArray(String[]::new))
                .build();
        fafnirClient.exportToFafnir(me);
        var result = hazelcastProvider.callback(UsernamePasswordCredentials.builder()
                .username("om@acto.dk")
                .password("omom")
                .build());
        var url = result.getUrl(fafnirConf);
        assertThat(url).contains("/fail#");
    }

    @Test
    void testWrongPasswordFailsFlow() {
        var me = FafnirUser.builder()
                .subject("om@acto.dk")
                .password("omom")
                .name("Oscar Mike")
                .provider("test")
                .organisationId("acto")
                .organisationName("Acto ApS")
                .metaId("meta")
                .locale(Locale.forLanguageTag("da-DK"))
                .roles(List.of("User", "Admin", "Site God").toArray(String[]::new))
                .created(Instant.MIN)
                .build();
        fafnirClient.exportToFafnir(fafnirClient.toSecureUser(me));
        var result = hazelcastProvider.callback(UsernamePasswordCredentials.builder()
                .username("om@acto.dk")
                .password("momo")
                .build());
        var url = result.getUrl(fafnirConf);
        assertThat(url).contains("/fail#");
    }

    @Test
    void testMinimalistSuccessFlow() {
        var me = FafnirUser.builder()
                .subject("om@acto.dk")
                .password("omom")
                .name("Oscar Mike")
                .build();
        fafnirClient.exportToFafnir(fafnirClient.toSecureUser(me));
        var result = hazelcastProvider.callback(UsernamePasswordCredentials.builder()
                .username("om@acto.dk")
                .password("omom")
                .build());
        var url = result.getUrl(fafnirConf);
        assertThat(url).contains("/success#");
        var matcher = JWT_MATCHER.matcher(url);
        assertThat(matcher.find()).isTrue();
        var jwt = matcher.group(1);
        var auth = jwtValidator.decodeToken(jwt);
        assertThat(auth.getUsername()).isEqualTo("om@acto.dk");
        assertThat(auth.getName()).isEqualTo("Oscar Mike");
        assertThat(auth.getMetaId()).isNull();
        assertThat(auth.hasMetaId()).isFalse();
        assertThat(auth.getPassword()).isNull();
        assertThat(auth.getDetails().getLocale()).isNull();
        assertThat(auth.getDetails().getOrganisationId()).isNull();
        assertThat(auth.getDetails().getOrganisationName()).isNull();
        assertThat(auth.getDetails().getRoles()).isEmpty();
        assertThat(auth.getDetails().getCreated()).isNotNull();
        assertThat(auth.getDetails().getCreated()).isNotEqualTo(Instant.MIN);
    }
}
