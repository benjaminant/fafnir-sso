package dk.acto.fafnir.server.provider;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.github.scribejava.apis.openid.OpenIdOAuth2AccessToken;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;
import dk.acto.fafnir.server.FailureReason;
import dk.acto.fafnir.server.TokenFactory;
import dk.acto.fafnir.server.model.CallbackResult;
import dk.acto.fafnir.api.model.FafnirUser;
import dk.acto.fafnir.server.provider.credentials.TokenCredentials;
import io.vavr.control.Option;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@Lazy
public class GoogleProvider implements RedirectingAuthenticationProvider<TokenCredentials> {
    private final OAuth20Service googleOauth;
    private final TokenFactory tokenFactory;

    public GoogleProvider(@Qualifier("googleOAuth") OAuth20Service googleOauth, TokenFactory tokenFactory) {
        this.googleOauth = googleOauth;
        this.tokenFactory = tokenFactory;
    }

    public String authenticate() {
        return googleOauth.getAuthorizationUrl();
    }

    @Override
    public CallbackResult callback(TokenCredentials data) {
        var code = data.getCode();
        final OAuth2AccessToken token = Option.of(code)
                .toTry()
                .mapTry(googleOauth::getAccessToken)
                .onFailure(x -> log.error("Authentication failed", x))
                .getOrNull();
        if (token == null) {
            return CallbackResult.failure(FailureReason.AUTHENTICATION_FAILED);
        }

        DecodedJWT jwtToken = JWT.decode(((OpenIdOAuth2AccessToken) token).getOpenIdToken());
        String subject = jwtToken.getClaims().get("email").asString();
        String displayName = jwtToken.getClaims().get("name").asString();

        String jwt = tokenFactory.generateToken(FafnirUser.builder()
                .subject(subject)
                .provider("google")
                .name(displayName)
                .organisationId(!jwtToken.getClaim("hd").isNull()
                        ? jwtToken.getClaim("hd").asString()
                        : null)
                .build());
        return CallbackResult.success(jwt);
    }
}
