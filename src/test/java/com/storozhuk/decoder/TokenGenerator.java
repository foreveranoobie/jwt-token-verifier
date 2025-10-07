package com.storozhuk.decoder;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class TokenGenerator {

    private final Algorithm algorithm;
    private String kid;
    private String iss;

    public TokenGenerator(KeyPair keyPair, String keyId, String issuer) {
        this.algorithm = Algorithm.RSA256((RSAPublicKey) keyPair.getPublic(),
            (RSAPrivateKey) keyPair.getPrivate());
        this.kid = keyId;
        this.iss = issuer;
    }

    /**
     * Generates a basic access token with custom parameters.
     *
     * @param expirationSeconds number of minutes until token expires
     * @param subject           the user subject
     * @param roles             list of user roles
     * @param permissions       list of user permissions
     * @return JWT token string
     */
    public String generateToken(String subject,
        List<String> roles, List<String> permissions, Instant currentTime, int expirationSeconds) {

        Instant expiration = currentTime.plus(expirationSeconds, ChronoUnit.SECONDS);

        return JWT.create()
            .withIssuer(iss + "/")
            .withSubject(subject)
            .withAudience("test-audience")
            .withExpiresAt(Date.from(expiration))
            .withIssuedAt(Date.from(currentTime))
            .withNotBefore(Date.from(currentTime))
            .withJWTId(UUID.randomUUID().toString())
            .withKeyId(kid)
            .withClaim("info/roles", roles)
            .withClaim("permissions", permissions)
            .withClaim("scope", "openid profile email")
            .sign(algorithm);
    }

}
