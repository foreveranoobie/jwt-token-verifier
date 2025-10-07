package com.storozhuk.decoder;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class AuthServiceUnitTest {

    private static final String DOMAIN = "http://localhost:8089";
    private static final String KEY_ID = "test-key-id";
    private final ObjectMapper objectMapper = new ObjectMapper();

    private AuthService authService;
    private TokenGenerator tokenGenerator;

    private WireMockServer wireMockServer;
    private KeyPair keyPair;

    @BeforeEach
    public void setUp() throws Exception {
        wireMockServer = new WireMockServer(8089);
        wireMockServer.start();
        WireMock.configureFor("localhost", 8089);

        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();

        // Setup AuthService with localhost domain
        authService = new AuthService(DOMAIN);

        // Mock JWKS endpoint
        setupJWKSMock();
        tokenGenerator = new TokenGenerator(keyPair, KEY_ID, DOMAIN);
    }

    @AfterEach
    void tearDown() {
        wireMockServer.stop();
    }

    private void setupJWKSMock() throws Exception {
        // Create JWKS response with our test public key
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        String modulus = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(publicKey.getModulus().toByteArray());
        String exponent = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(publicKey.getPublicExponent().toByteArray());

        Map<String, Object> jwksResponse = Map.of("keys", List.of(
            Map.of("kty", "RSA", "use", "sig", "kid", KEY_ID, "n", modulus, "e", exponent, "alg",
                "RS256", "iss", DOMAIN + "/")));

        String jwksJson = objectMapper.writeValueAsString(jwksResponse);

        stubFor(get(urlEqualTo("/.well-known/jwks.json")).willReturn(
            aResponse().withStatus(200).withHeader("Content-Type", "application/json")
                .withBody(jwksJson)));
    }

    @Test
    public void shouldReturnUserInfo_whenValidateToken_givenValidToken() {
        //given
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plus(10, ChronoUnit.SECONDS);

        UserInfo expectedUser = new UserInfo("test-subject", List.of("test-role"),
            List.of("test-permission"), now, expiration);
        String givenToken = tokenGenerator.generateToken("test-subject", List.of("test-role"),
            List.of("test-permission"), now, 10);

        //when
        UserInfo actualUser = authService.validateToken(givenToken);

        //then
        assertThat(actualUser).usingRecursiveComparison().isEqualTo(expectedUser);
    }


    @Test
    public void shouldReturnTrue_whenIsTokenNotExpired_givenNotExpiredToken() {
        //given
        Instant now = Instant.now();
        String givenToken = tokenGenerator.generateToken(null, null, null, now, 10);

        //when
        boolean actualResult = authService.isTokenNotExpired(givenToken);

        //then
        assertTrue(actualResult);
    }

    @Test
    public void shouldReturnFalse_whenIsTokenNotExpired_givenExpiredToken() {
        //given
        Instant now = Instant.now();
        String givenToken = tokenGenerator.generateToken(null, null, null, now, 0);

        //when
        boolean actualResult = authService.isTokenNotExpired(givenToken);

        //then
        assertFalse(actualResult);
    }

}
