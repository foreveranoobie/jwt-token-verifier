package com.storozhuk.decoder;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

public class AuthService {

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final String domain;

    public AuthService(String domain) {
        this.domain = domain;
    }

    private RSAPublicKey getPublicKey(String keyId) throws Exception {
        // Fetch JWKS from Auth0
        String jwksUrl = domain + "/.well-known/jwks.json";
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(jwksUrl))
            .GET()
            .build();

        HttpResponse<String> response = httpClient.send(request,
            HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new RuntimeException("Failed to fetch JWKS: " + response.statusCode());
        }

        // Parse JWKS JSON
        JsonNode jwks = objectMapper.readTree(response.body());
        JsonNode keys = jwks.get("keys");

        for (JsonNode key : keys) {
            if (keyId.equals(key.get("kid").asText())) {
                return buildRSAPublicKey(key);
            }
        }

        throw new RuntimeException("Key not found: " + keyId);
    }

    private RSAPublicKey buildRSAPublicKey(JsonNode key) throws Exception {
        String nStr = key.get("n").asText();
        String eStr = key.get("e").asText();

        // Decode base64url
        byte[] nBytes = Base64.getUrlDecoder().decode(nStr);
        byte[] eBytes = Base64.getUrlDecoder().decode(eStr);

        BigInteger modulus = new BigInteger(1, nBytes);
        BigInteger exponent = new BigInteger(1, eBytes);

        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory factory = KeyFactory.getInstance("RSA");

        return (RSAPublicKey) factory.generatePublic(spec);
    }

    public UserInfo validateToken(String token) {
        try {
            // First decode to get the key ID
            DecodedJWT unverifiedJwt = JWT.decode(token);
            String keyId = unverifiedJwt.getKeyId();

            // Get the public key
            RSAPublicKey publicKey = getPublicKey(keyId);

            // Verify the token
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            DecodedJWT jwt = JWT.require(algorithm)
                .withIssuer(domain + "/")
                .build()
                .verify(token);

            // Extract roles (adjust claim name based on your Auth0 configuration)
            List<String> roles = jwt.getClaim("roles").asList(String.class);

            return new UserInfo(jwt.getSubject(), roles);

        } catch (Exception e) {
            throw new RuntimeException("Invalid token: " + e.getMessage(), e);
        }
    }

    /**
     * Validates if an access token is not expired. This method only checks the expiration claim
     * without performing signature verification.
     *
     * @param token the JWT token to check
     * @return true if the token is not expired, false otherwise
     * @throws RuntimeException if the token is malformed or doesn't contain an expiration claim
     */
    public boolean isTokenNotExpired(String token) {
        try {
            // Decode the token without verification to check expiration
            DecodedJWT jwt = JWT.decode(token);

            // Get the expiration time from the 'exp' claim
            Instant expirationTime = jwt.getExpiresAtAsInstant();

            if (expirationTime == null) {
                throw new RuntimeException("Token does not contain expiration claim");
            }

            // Check if the current time is before expiration time
            return Instant.now().isBefore(expirationTime);

        } catch (Exception e) {
            throw new RuntimeException("Invalid token format: " + e.getMessage(), e);
        }
    }

}