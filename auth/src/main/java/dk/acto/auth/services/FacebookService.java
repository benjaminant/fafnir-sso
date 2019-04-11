package dk.acto.auth.services;

import dk.acto.auth.ActoConf;
import dk.acto.auth.providers.FacebookProvider;
import dk.acto.auth.providers.validators.FacebookValidator;
import io.vavr.control.Try;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;

@RestController
@Slf4j
@RequestMapping("facebook")
public class FacebookService implements CallbackService{
    private final FacebookProvider provider;
    private final ActoConf actoConf;

    @Autowired
    public FacebookService(FacebookProvider provider, @Validated(FacebookValidator.class) ActoConf actoConf) {
        this.provider = provider;
        this.actoConf = actoConf;
    }

    @GetMapping
    public void authenticate(HttpServletResponse response) {
        Try.of(() -> ServiceHelper.functionalRedirectTo(response, provider::authenticate));
    }

    @GetMapping("callback")
    public void callback(HttpServletResponse response, @RequestParam String code) {
        Try.of(() -> ServiceHelper.functionalRedirectTo(response, () -> provider.callback(code)));
    }
}
