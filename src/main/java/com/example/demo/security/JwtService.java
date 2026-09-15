package com.example.demo.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

/**
 * Issues and validates JWTs.
 *
 * Token creation (B2.4/B2.8) and token validation (needed for the
 * JwtAuthenticationFilter protecting POST /api/auth/users) both live here,
 * sharing the same signing key/config — no separate "validator" class.
 */
@Component
public class JwtService {

    private final SecretKey signingKey;
    private final long expirationMs;

    public JwtService(
            @Value("${jwt.secret}") String base64Secret,
            @Value("${jwt.expiration-ms}") long expirationMs) {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(base64Secret));
        this.expirationMs = expirationMs;
    }

    /**
     * Builds a signed JWT with the username as subject and the user's role
     * as a custom claim, per the LoginResponse contract in the swagger spec.
     */
    public String generateToken(String username, String role) {
        Date issuedAt = new Date();
        Date expiresAt = new Date(issuedAt.getTime() + expirationMs);

        return Jwts.builder()
                .subject(username)
                .claim("role", role)
                .issuedAt(issuedAt)
                .expiration(expiresAt)
                .signWith(signingKey)
                .compact();
    }

    /**
     * Validates the signature and expiration, and returns the claims
     * (subject = username, "role" claim) on success.
     *
     * Throws io.jsonwebtoken.JwtException (or a subclass — ExpiredJwtException,
     * SignatureException, MalformedJwtException, etc.) for anything invalid.
     * JwtAuthenticationFilter catches that and treats the request as
     * unauthenticated, which the security config turns into a 401.
     */
    public Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /** Seconds until expiry — feeds LoginResponse.expiresIn. */
    public long getExpirationSeconds() {
        return expirationMs / 1000;
    }
}

