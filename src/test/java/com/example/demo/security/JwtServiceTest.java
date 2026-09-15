package com.example.demo.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtServiceTest {

    private static final String TEST_SECRET = "wELlrzgLdgUqv1gGrvgQmx9153+14FyGO34AYx0rxGs=";
    private static final long TEST_EXPIRATION_MS = 36000000L;

    private JwtService jwtService;
    private SecretKey verificationKey;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService(TEST_SECRET, TEST_EXPIRATION_MS);
        verificationKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(TEST_SECRET));
    }

    @Test
    void generateToken_ContainsUsernameAndRoleClaims() {
        String token = jwtService.generateToken("akshat_user", "ADMIN");
        assertNotNull(token);

        Claims claims = Jwts.parser()
                .verifyWith(verificationKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        assertEquals("akshat_user", claims.getSubject());
        assertEquals("ADMIN", claims.get("role", String.class));
        assertNotNull(claims.getIssuedAt());
        assertNotNull(claims.getExpiration());
        assertTrue(claims.getExpiration().after(claims.getIssuedAt()));
    }

    @Test
    void getExpirationSeconds_ConvertsConfiguredMillisecondsToSeconds() {
        assertEquals(36000L, jwtService.getExpirationSeconds());
    }

    @Test
    void parseToken_ValidToken_ReturnsMatchingClaims() {
        String token = jwtService.generateToken("officer01", "BANK_OFFICER");

        Claims claims = jwtService.parseToken(token);

        assertEquals("officer01", claims.getSubject());
        assertEquals("BANK_OFFICER", claims.get("role", String.class));
    }

    @Test
    void parseToken_ExpiredToken_ThrowsJwtException() {
        // Build a token that already expired 1 second ago, using the same key.
        Date past = new Date(System.currentTimeMillis() - 60_000);
        Date evenFurtherPast = new Date(past.getTime() - 60_000);
        String expiredToken = Jwts.builder()
                .subject("officer01")
                .claim("role", "BANK_OFFICER")
                .issuedAt(evenFurtherPast)
                .expiration(past)
                .signWith(verificationKey)
                .compact();

        assertThrows(ExpiredJwtException.class, () -> jwtService.parseToken(expiredToken));
    }

    @Test
    void parseToken_TamperedSignature_ThrowsJwtException() {
        String token = jwtService.generateToken("officer01", "BANK_OFFICER");
        // Flip the last character of the signature so verification fails.
        char lastChar = token.charAt(token.length() - 1);
        char replacement = lastChar == 'A' ? 'B' : 'A';
        String tamperedToken = token.substring(0, token.length() - 1) + replacement;

        assertThrows(JwtException.class, () -> jwtService.parseToken(tamperedToken));
    }
}
