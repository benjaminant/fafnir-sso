package dk.acto.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.google.common.io.BaseEncoding;
import io.vavr.control.Try;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Date;

@Component
public class TokenFactory {

	private final KeyPair keys;

	public TokenFactory() {
		this.keys = Try.of(() -> KeyPairGenerator.getInstance("RSA"))
				.andThen(x -> x.initialize(1024, new SecureRandom()))
				.map(KeyPairGenerator::generateKeyPair)
				.get();
	}

	public String generateToken(String subject, String idp, String name) {
		return Try.of(() -> Algorithm.RSA512((RSAPublicKey) keys.getPublic(), (RSAPrivateKey) keys.getPrivate()))
				.map(x -> JWT.create()
						.withIssuer("fafnir-" + idp)
						.withSubject(subject)
						.withIssuedAt(Date.from(ZonedDateTime.now().toInstant()))
						.withClaim("name", name)
						.sign(x))
				.get();
	}

	public String generateToken(String subject, String idp, String name, String locale) {
		return Try.of(() -> Algorithm.RSA512((RSAPublicKey) keys.getPublic(), (RSAPrivateKey) keys.getPrivate()))
				.map(x -> JWT.create()
						.withIssuer("fafnir-" + idp)
						.withSubject(subject)
						.withIssuedAt(Date.from(ZonedDateTime.now().toInstant()))
						.withClaim("name", name)
						.withClaim("locale", locale )
						.sign(x))
				.get();
	}

	public String generateToken(String subject, String idp, String userFullName, String organisationId, String organisationName, String[] roles) {
		return Try.of(() -> Algorithm.RSA512((RSAPublicKey) keys.getPublic(), (RSAPrivateKey) keys.getPrivate()))
				.map(x -> JWT.create()
						.withIssuer("fafnir-" + idp)
						.withSubject(subject)
						.withIssuedAt(Date.from(ZonedDateTime.now().toInstant()))
						.withClaim("name", userFullName)
						.withClaim("org_id", organisationId)
						.withClaim("org_name", organisationName)
						.withArrayClaim("role", roles)
						.sign(x))
				.get();
	}

	public String getPublicKey() {
		return BaseEncoding.base64().omitPadding().encode(
				keys.getPublic().getEncoded()
		);
	}

	public String decryptString(String encrypted) {
		return Try.of(() -> Cipher.getInstance("RSA/ECB/PKCS1Padding"))
				.andThenTry(x -> x.init(Cipher.DECRYPT_MODE, keys.getPrivate()))
				.mapTry(x -> x.doFinal(Base64.getDecoder().decode(encrypted)))
				.map(x -> new String(x, StandardCharsets.UTF_8))
				.getOrNull();
	}
}
